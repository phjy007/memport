#include <iostream>
#include "llvm/Support/raw_os_ostream.h"
#include "ClangSACheckers.h"
#include "clang/AST/Type.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Store.h"
#include "clang/StaticAnalyzer/Core/BugReporter/PathDiagnostic.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include <sstream>
using namespace clang;
using namespace ento;
using namespace std;
using namespace llvm;
#define ZXMYS_DEBUG 1
#define ZXMYS_DEBUG_OUT if(ZXMYS_DEBUG)
#define ZXMYS_DEBUG_PRINT(x) ZXMYS_DEBUG_OUT cout<<x<<endl;

typedef struct {
	int reg_num;
	int endian; //0 for l, 1 for b;
	int padding;  //??
	int alignment; //minium alignment 
	int *varsize;
} platform_memory;

namespace {
    class MemoryAccessChecker: public Checker<check::Location,check::PreStmt<DeclStmt>,check::BranchCondition > {
        mutable OwningPtr<BuiltinBug> BT;
		mutable raw_os_ostream *rout;
    public:
        void checkPreStmt(const DeclStmt *DS, CheckerContext &Ctx) const;
        void checkLocation(SVal l, bool isLoad, const Stmt* S,
                           CheckerContext &C) const;
		void checkBranchCondition(const Stmt *Condition, CheckerContext &Ctx) const;
		bool accessUnion(const MemRegion* region,const QualType* type,bool isLoad) const;
		const MemRegion* getSuperRegion(const MemRegion*& subregion) const;
		const SymbolRegionValue* getSymbolRegionValue(const SymbolicRegion*& region) const;
		const Type* getRegionType(const MemRegion *&subregion,CheckerContext &C) const;
		MemoryAccessChecker();
		~MemoryAccessChecker();
    };
}


void MemoryAccessChecker::checkPreStmt(const DeclStmt *DS, CheckerContext &C) const{
    ZXMYS_DEBUG_OUT cout<<"!!!!!preStmt ";
    ZXMYS_DEBUG_OUT cout<<DS->getStmtClassName()<<endl<<endl;
}

void MemoryAccessChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
    ZXMYS_DEBUG_OUT cout<<"!!!!!branchCondition "<<flush;
	ZXMYS_DEBUG_OUT Condition->dumpPretty(C.getASTContext());
    ZXMYS_DEBUG_OUT cout<<endl<<endl;
}

MemoryAccessChecker::MemoryAccessChecker(){
	rout=new raw_os_ostream(cout);
}


MemoryAccessChecker::~MemoryAccessChecker(){
	delete rout;
}

bool MemoryAccessChecker::accessUnion(const MemRegion* region,const QualType* type,bool isLoad) const{
	return true;
}

const MemRegion* MemoryAccessChecker::getSuperRegion(const MemRegion*& subregion) const{
	//const TypedValueRegion *tvr=R->getAs<TypedValueRegion>();
	const SubRegion *SR = dyn_cast<SubRegion>(subregion);
	if(!SR){
		const ElementRegion* ER=dyn_cast<ElementRegion>(subregion);
		if(!ER)
			return NULL;
		else 
			return ER->getSuperRegion();
	}
	return SR->getSuperRegion();
}

const SymbolRegionValue *MemoryAccessChecker::getSymbolRegionValue(const SymbolicRegion*& sr) const{
	const SymbolRegionValue *Sm =dyn_cast<SymbolRegionValue>(sr->getSymbol());
	return Sm;
}

const Type* MemoryAccessChecker::getRegionType(const MemRegion *&subregion,CheckerContext &C) const{
    //ZXMYS_DEBUG_OUT cout<<"try to get type for region "<<subregion<<endl;  
	const MemRegion* superRegion=subregion;
	if(!superRegion)
		return NULL;
	const VarRegion* supervr=dyn_cast<VarRegion>(superRegion);
	if(supervr)
		return (supervr->getValueType().getUnqualifiedType())->getAs<Type>();
	const SymbolicRegion* supersr=dyn_cast<SymbolicRegion>(superRegion);
	if(supersr){
		const SymbolRegionValue *supersrv=getSymbolRegionValue(supersr);
		if(supersrv){
			const Type* ret=((supersrv->getType(C.getASTContext())).getUnqualifiedType())->getAs<Type>();
			if(ret){
				if(ret->isPointerType()){
								ret=(supersrv->getType(C.getASTContext()).getUnqualifiedType())->getAs<PointerType>();
								return (ret->getPointeeType().getUnqualifiedType())->getAs<Type>();
				}else
					return ret;
			}
		}
		const SymbolConjured *supersc =dyn_cast<SymbolConjured>(supersr->getSymbol());	
		if(supersc){
			const Type* ret=(supersc->getType(C.getASTContext()).getUnqualifiedType())->getAs<Type>();
			if(ret->isPointerType()){
				ret=(supersc->getType(C.getASTContext()).getUnqualifiedType())->getAs<PointerType>();
				return (ret->getPointeeType().getUnqualifiedType())->getAs<Type>();
			}else
				return ret;
		}
	}
	
	const ElementRegion* ER=dyn_cast<ElementRegion>(superRegion);
	if(ER)
		return (ER->getValueType().getUnqualifiedType())->getAs<Type>();
		
	const FieldRegion* FR=dyn_cast<FieldRegion>(superRegion);
	if(FR)
		return (FR->getValueType().getUnqualifiedType())->getAs<Type>();
	
	return NULL;
}


void MemoryAccessChecker::checkLocation(SVal l, bool isLoad, const Stmt* S,
                               CheckerContext &C) const {
    ZXMYS_DEBUG_OUT cout<<"-----\nisLoad: "<<isLoad<<endl;   
	
    ProgramStateRef state = C.getState();
	SValBuilder& svalBuilder=C.getSValBuilder();
	const Store store = state->getStore();
	const StoreManager& storeManager=C.getStoreManager();
    const MemRegion* R = l.getAsRegion();


    cout << "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" << endl;
    cout << "OLD_programstate.................." << endl;
    state->dump();
    cout << endl;

    SVal yjySVal = svalBuilder.makeIntVal(31415926, false);
    Loc newLoc = svalBuilder.makeLoc(R);
    cout << "newLoc: " << flush;
    newLoc.dump();
    cout << endl;
    state = state->bindLoc(svalBuilder.makeLoc(R), yjySVal);
    C.addTransition(state);
    
    cout << "new_programstate.................." << endl;
    state->dump();
    cout << endl;
    
    cout << "Store:" << endl;
    *rout << store;
    rout->flush();
    cout << endl;
    cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;


	if(!R)
		return;
    //cout << "R: " << flush;
    //R->dump();
	SVal regionVal,superRegionVal;
	regionVal=state->getSVal(R);
	const MemRegion* superRegion=getSuperRegion(R);
	if(!superRegion)
		return;
	
	const SubRegion* subR=dyn_cast<SubRegion>(R);
	DefinedOrUnknownSVal subExtent=subR->getExtent(svalBuilder);	
	ZXMYS_DEBUG_OUT cout<<"subRegion ";
	ZXMYS_DEBUG_OUT *rout<<R;
	ZXMYS_DEBUG_OUT *rout<<" size:";
	ZXMYS_DEBUG_OUT *rout<<subExtent;
	ZXMYS_DEBUG_OUT rout->flush();
	ZXMYS_DEBUG_OUT cout<<endl;	
	ZXMYS_DEBUG_OUT cout<<"subRegion Base Region ";
	ZXMYS_DEBUG_OUT *rout<<R->getBaseRegion();
	ZXMYS_DEBUG_OUT rout->flush();
	ZXMYS_DEBUG_OUT cout<<endl;	
	ZXMYS_DEBUG_OUT cout<<"subRegion Space Region ";
	ZXMYS_DEBUG_OUT *rout<<R->getMemorySpace();
	ZXMYS_DEBUG_OUT rout->flush();
	ZXMYS_DEBUG_OUT cout<<" hasGlobalsOrParametersStorage? "<<R->getBaseRegion()->hasGlobalsOrParametersStorage();	
	ZXMYS_DEBUG_OUT cout<<" hasStackStorage? "<<R->getBaseRegion()->hasStackStorage();
	if(isa<SymbolicRegion>(R->getBaseRegion())){
		ZXMYS_DEBUG_OUT cout<<" symbol region? ";
		const SymbolicRegion* tmpsr=dyn_cast<SymbolicRegion>(R->getBaseRegion());
		const MemRegion* tmpreg=getSymbolRegionValue(tmpsr)->getRegion();
		ZXMYS_DEBUG_OUT *rout<<tmpreg;
		ZXMYS_DEBUG_OUT rout->flush();
		ZXMYS_DEBUG_OUT cout<<" hasGlobalsOrParametersStorage? "<<tmpreg->hasGlobalsOrParametersStorage();	
		ZXMYS_DEBUG_OUT cout<<" hasStackStorage? "<<tmpreg->hasStackStorage();
		
	}
	ZXMYS_DEBUG_OUT cout<<endl;	
	
	const Type* superRegionType=getRegionType(superRegion,C);
	//const QualType* superRegionQT=superRegionType->getAs<QualType>();
	const Type* regionType=getRegionType(R,C);
	//const QualType* regionQT=regionType->getAs<QualType>();
	
	if(!superRegionType)
		return;
	
	superRegionVal=state->getSVal(superRegion);
	if(regionType){
		ZXMYS_DEBUG_OUT cout<<"subRegionType "<<(regionType->getCanonicalTypeInternal()).getAsString()<<endl;
		ZXMYS_DEBUG_OUT cout<<"subRegionVal ";
		ZXMYS_DEBUG_OUT *rout<<regionVal;
		ZXMYS_DEBUG_OUT rout->flush();
		ZXMYS_DEBUG_OUT cout<<endl;	
	}	
	ZXMYS_DEBUG_OUT cout<<endl;
	ZXMYS_DEBUG_OUT cout<<"superRegion ";
	ZXMYS_DEBUG_OUT *rout<<superRegion;
	ZXMYS_DEBUG_OUT *rout<<" size:";
	if(dyn_cast<SubRegion>(superRegion))
		ZXMYS_DEBUG_OUT *rout<<dyn_cast<SubRegion>(superRegion)->getExtent(svalBuilder);
	else
		ZXMYS_DEBUG_OUT *rout<<"don't know";
	ZXMYS_DEBUG_OUT rout->flush();
	ZXMYS_DEBUG_OUT cout<<endl;	
	ZXMYS_DEBUG_OUT cout<<"superRegionType "<<(superRegionType->getCanonicalTypeInternal()).getAsString()<<endl;
	ZXMYS_DEBUG_OUT cout<<"superRegionVal ";	
	ZXMYS_DEBUG_OUT *rout<<superRegionVal;
	ZXMYS_DEBUG_OUT rout->flush();
	ZXMYS_DEBUG_OUT cout<<endl;	
		
	if(superRegionType->isUnionType())
		goto FINDBUG;
	
	if(superRegionType->isStructureType()&&R->getKind()==MemRegion::FieldRegionKind)
		return;
	
	if(superRegionType->isArrayType())
		return;
	
	//todo: consider this
	//if(!(superRegionType->getCanonicalTypeInternal().getAsString().compare("void")))
	//	return;
		
	//if(!(superRegionType->getCanonicalTypeInternal().getAsString().compare("char")))
	//	return;
		
	if(regionType)
		if(superRegionType->getCanonicalTypeInternal().getAsString().compare(regionType->getCanonicalTypeInternal().getAsString()))
			goto FINDBUG;
						
    
	return;
	
	
FINDBUG:	
	
	ZXMYS_DEBUG_OUT cout<<"!!!Found bug here!!!"<<endl;
	ostringstream o;
	o<<"This memory access is endian/alignment-dependent : ";
	o<<R->getString();
	o<<" , is load: ";
	o<<isLoad;
	o<<" , superRegionType:";
	o<<(superRegionType->getCanonicalTypeInternal()).getAsString();
	o<<" , subRegionType:";
	if(regionType)
		o<<(regionType->getCanonicalTypeInternal()).getAsString();
	else
		o<<"NULL";
    if (!BT)
        BT.reset(new BuiltinBug("Endian/Alignment-Related memory access",
                                ""));
	
	//to do : remove this reduntant memory management
    char *desc=strdup(o.str().c_str());
    BugReport *report = new BugReport(*BT, desc, C.generateSink());
    free(desc);
	
	report->markInteresting(R);
    report->addRange(S->getSourceRange());
    C.EmitReport(report);
    return;
    
    
    
    
}

void ento::registerMemoryAccessChecker(CheckerManager &mgr) {
    mgr.registerChecker<MemoryAccessChecker>();
}



