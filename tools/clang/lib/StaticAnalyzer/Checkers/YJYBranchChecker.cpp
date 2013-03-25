#include <iostream>
#include "llvm/Support/raw_os_ostream.h"
#include "ClangSACheckers.h"
#include "clang/AST/Type.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/PathDiagnostic.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include <sstream>
using namespace clang;
using namespace ento;
using namespace std;
using namespace llvm;


namespace {
    class YJYBranchChecker: public Checker<check::PreStmt<Stmt>, check::BranchCondition, check::PostStmt<Stmt> > {
        mutable OwningPtr<BuiltinBug> BT;
		mutable raw_os_ostream *rout;
    public:
        void checkPreStmt(const Stmt *DS, CheckerContext &Ctx) const;
		void checkBranchCondition(const Stmt *Condition, CheckerContext &Ctx) const;
        void checkPostStmt(const Stmt *DS, CheckerContext &C) const;
        // void checkLocation(SVal l, bool isLoad, const Stmt* S, CheckerContext &C) const;
		YJYBranchChecker();
		~YJYBranchChecker();
    };
}

void YJYBranchChecker::checkPreStmt(const Stmt *DS, CheckerContext &C) const {
    //cout << "PRE_STMT==============================================================" << endl;
    //cout << DS->getStmtClassName() << endl;
    //cout << "Statement:" << endl;
    //DS->dump();

    //ProgramStateRef state = C.getState();
    //cout << "ProgramState:" << endl;
    //state->dump();
    //cout << flush;

    // Dump the CFG
    //const LocationContext* LCtx = C.getLocationContext();
    //CFG *cfg_block = LCtx->getCFG();
    //cfg_block->dump(C.getAnalysisManager().getLangOpts(), true);
    //cout << "**** &&&&& (((((( )))))) @@@@@@@@@@@@" << endl;

    //const LocationContext* LCtx = C.getLocationContext();
    //SVal sval = state->getSVal(DS, LCtx);
    //cout << "SVal.isValid = " << sval.isValid() << flush << endl;
    //cout << "SVal.dump(): " << flush;
    //sval.dump();
    //if(sval.isValid()) {
    //    //const MemRegion* region = sval.getAsRegion();
    //    //*rout<<region;
    //    
    //}
    //cout << endl << endl;
}

void YJYBranchChecker::checkPostStmt(const Stmt *DS, CheckerContext &C) const {
    //cout << "POST_STMT==============================================================" << endl;
    //cout << DS->getStmtClassName() << endl;
    //DS->dump();

    //ProgramStateRef state = C.getState();

    //const LocationContext* LCtx = C.getLocationContext();
    //SVal sval = state->getSVal(DS, LCtx);
    //cout << "SVal.isValid = " << sval.isValid() << flush << endl;
    //cout << "SVal.dump(): " << flush;
    ////sval.dump();
    //*rout << sval;
    //cout << endl << "SVal.BaseKind(): " << sval.getBaseKind() << endl;

    ////cout << "Store: ";
    ////const Store store = state->getStore();
    ////*rout << store;
    //
    //SValBuilder& svalBuilder = C.getSValBuilder();
    //SVal yjySVal = svalBuilder.makeIntVal(31415926, false);
    //cout << "yjySVal: " << flush;
    //yjySVal.dump();
    //cout << endl;

    //const MemRegion* R = sval.getAsRegion();
    //cout << "MemRegion: " << flush;
    //*rout << R;

    //Loc newLoc = svalBuilder.makeLoc(R);
    //cout << "newLoc: " << flush;
    //newLoc.dump();
    //cout << endl;
    //StoreManager& storeManager = C.getStoreManager();
    //const Store store = state->getStore();
    ////StoreRef storeRef = storeManager.Bind(store, newLoc, (SVal)yjySVal);
    //
    //cout << "new_programstate.................." << endl;
    //cout << DS->getStmtClassName() << endl;
    //DS->dump();

    //cout << endl << endl;
}

void YJYBranchChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
    cout << "CONDITION:............................................ " << endl;
	Condition->dumpPretty(C.getASTContext());
    cout << endl;

    //ProgramStateRef state = C.getState();
    //cout << "ProgramState:" << endl;
    //state->dump();
    //cout << flush;


    //Environment env = state->getEnvironment();

    //LocationContext lctx = C.getLocationContext();
    //SVal sval = state->getSVal(Condition, lctx);
    //sval->dump();

    //Store store = state->getStore();
    //StoreManager& storeManager = C.getStoreManager();

    //ExplodedNode *Pred = C.getPredecessor();
    //SVal sval = state->getSVal(Condition, Pred->getLocationContext());
    //sval.dump();
    
    //SVal sval = C.getSVal(Condition);
    //cout << "SVal:" << endl;
    //sval.dump();

    //SValBuilder& svalBuilder=C.getSValBuilder();
    //cout << endl << endl;

}

YJYBranchChecker::YJYBranchChecker() {
	rout = new raw_os_ostream(cout);
}


YJYBranchChecker::~YJYBranchChecker() {
	delete rout;
}


// void YJYBranchChecker::checkLocation(SVal l, bool isLoad, const Stmt* S,
//                                CheckerContext &C) const {
							
//     ZXMYS_DEBUG_OUT cout<<"-----\nisLoad: "<<isLoad<<endl;
//     ProgramStateRef state = C.getState();
// 	SValBuilder& svalBuilder=C.getSValBuilder();
// 	const Store store = state->getStore();
// 	const StoreManager& storeManager=C.getStoreManager();
//     const MemRegion* R = l.getAsRegion();
// 	if(!R)
// 		return;
// 	SVal regionVal,superRegionVal;
// 	regionVal=state->getSVal(R);
// 	const MemRegion* superRegion=getSuperRegion(R);
// 	if(!superRegion)
// 		return;
	
// 	const SubRegion* subR=dyn_cast<SubRegion>(R);
// 	DefinedOrUnknownSVal subExtent=subR->getExtent(svalBuilder);	
// 	ZXMYS_DEBUG_OUT cout<<"subRegion ";
// 	ZXMYS_DEBUG_OUT *rout<<R;
// 	ZXMYS_DEBUG_OUT *rout<<" size:";
// 	ZXMYS_DEBUG_OUT *rout<<subExtent;
// 	ZXMYS_DEBUG_OUT rout->flush();
// 	ZXMYS_DEBUG_OUT cout<<endl;	
// 	ZXMYS_DEBUG_OUT cout<<"subRegion Base Region ";
// 	ZXMYS_DEBUG_OUT *rout<<R->getBaseRegion();
// 	ZXMYS_DEBUG_OUT rout->flush();
// 	ZXMYS_DEBUG_OUT cout<<endl;	
// 	ZXMYS_DEBUG_OUT cout<<"subRegion Space Region ";
// 	ZXMYS_DEBUG_OUT *rout<<R->getMemorySpace();
// 	ZXMYS_DEBUG_OUT rout->flush();
// 	ZXMYS_DEBUG_OUT cout<<" hasGlobalsOrParametersStorage? "<<R->getBaseRegion()->hasGlobalsOrParametersStorage();	
// 	ZXMYS_DEBUG_OUT cout<<" hasStackStorage? "<<R->getBaseRegion()->hasStackStorage();
// 	if(isa<SymbolicRegion>(R->getBaseRegion())){
// 		ZXMYS_DEBUG_OUT cout<<" symbol region? ";
// 		const SymbolicRegion* tmpsr=dyn_cast<SymbolicRegion>(R->getBaseRegion());
// 		const MemRegion* tmpreg=getSymbolRegionValue(tmpsr)->getRegion();
// 		ZXMYS_DEBUG_OUT *rout<<tmpreg; ZXMYS_DEBUG_OUT rout->flush();
// 		ZXMYS_DEBUG_OUT cout<<" hasGlobalsOrParametersStorage? "<<tmpreg->hasGlobalsOrParametersStorage();	
// 		ZXMYS_DEBUG_OUT cout<<" hasStackStorage? "<<tmpreg->hasStackStorage();
		
// 	}
// 	ZXMYS_DEBUG_OUT cout<<endl;	
	
// 	const Type* superRegionType=getRegionType(superRegion,C);
// 	//const QualType* superRegionQT=superRegionType->getAs<QualType>();
// 	const Type* regionType=getRegionType(R,C);
// 	//const QualType* regionQT=regionType->getAs<QualType>();
	
// 	if(!superRegionType)
// 		return;
	
// 	superRegionVal=state->getSVal(superRegion);
// 	if(regionType){
// 		ZXMYS_DEBUG_OUT cout<<"subRegionType "<<(regionType->getCanonicalTypeInternal()).getAsString()<<endl;
// 		ZXMYS_DEBUG_OUT cout<<"subRegionVal ";
// 		ZXMYS_DEBUG_OUT *rout<<regionVal;
// 		ZXMYS_DEBUG_OUT rout->flush();
// 		ZXMYS_DEBUG_OUT cout<<endl;	
// 	}	
// 	ZXMYS_DEBUG_OUT cout<<endl;
// 	ZXMYS_DEBUG_OUT cout<<"superRegion ";
// 	ZXMYS_DEBUG_OUT *rout<<superRegion;
// 	ZXMYS_DEBUG_OUT *rout<<" size:";
// 	if(dyn_cast<SubRegion>(superRegion))
// 		ZXMYS_DEBUG_OUT *rout<<dyn_cast<SubRegion>(superRegion)->getExtent(svalBuilder);
// 	else
// 		ZXMYS_DEBUG_OUT *rout<<"don't know";
// 	ZXMYS_DEBUG_OUT rout->flush();
// 	ZXMYS_DEBUG_OUT cout<<endl;	
// 	ZXMYS_DEBUG_OUT cout<<"superRegionType "<<(superRegionType->getCanonicalTypeInternal()).getAsString()<<endl;
// 	ZXMYS_DEBUG_OUT cout<<"superRegionVal ";	
// 	ZXMYS_DEBUG_OUT *rout<<superRegionVal;
// 	ZXMYS_DEBUG_OUT rout->flush();
// 	ZXMYS_DEBUG_OUT cout<<endl;	
		
// 	if(superRegionType->isUnionType())
// 		goto FINDBUG;
	
// 	if(superRegionType->isStructureType()&&R->getKind()==MemRegion::FieldRegionKind)
// 		return;
	
// 	if(superRegionType->isArrayType())
// 		return;
	
// 	//todo: consider this
// 	//if(!(superRegionType->getCanonicalTypeInternal().getAsString().compare("void")))
// 	//	return;
		
// 	//if(!(superRegionType->getCanonicalTypeInternal().getAsString().compare("char")))
// 	//	return;
		
// 	if(regionType)
// 		if(superRegionType->getCanonicalTypeInternal().getAsString().compare(regionType->getCanonicalTypeInternal().getAsString()))
// 			goto FINDBUG;
						
    
// 	return;
	
	
// FINDBUG:	
	
// 	ZXMYS_DEBUG_OUT cout<<"!!!Found bug here!!!"<<endl;
// 	ostringstream o;
// 	o<<"This memory access is endian/alignment-dependent : ";
// 	o<<R->getString();
// 	o<<" , is load: ";
// 	o<<isLoad;
// 	o<<" , superRegionType:";
// 	o<<(superRegionType->getCanonicalTypeInternal()).getAsString();
// 	o<<" , subRegionType:";
// 	if(regionType)
// 		o<<(regionType->getCanonicalTypeInternal()).getAsString();
// 	else
// 		o<<"NULL";
//     if (!BT)
//         BT.reset(new BuiltinBug("Endian/Alignment-Related memory access",
//                                 ""));
	
// 	//to do : remove this reduntant memory management
//     char *desc=strdup(o.str().c_str());
//     BugReport *report = new BugReport(*BT, desc, C.generateSink());
//     free(desc);
	
// 	report->markInteresting(R);
//     report->addRange(S->getSourceRange());
//     C.EmitReport(report);
//     return;
    
    
// }

void ento::registerYJYBranchChecker(CheckerManager &mgr) {
    mgr.registerChecker<YJYBranchChecker>();
}



