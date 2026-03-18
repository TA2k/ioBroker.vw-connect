.class final Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleManagerImpl;->registerVehicles-gIAlu-s(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lay0/a;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field final synthetic $continuation:Lkotlin/coroutines/Continuation;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lkotlin/coroutines/Continuation<",
            "Ljava/util/List<",
            "+",
            "Ltechnology/cariad/cat/genx/GenXError;",
            ">;>;"
        }
    .end annotation
.end field

.field final synthetic $vehicleInformation:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ltechnology/cariad/cat/genx/Vehicle$Information;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/util/List;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleManagerImpl;",
            "Ljava/util/List<",
            "Ltechnology/cariad/cat/genx/Vehicle$Information;",
            ">;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ljava/util/List<",
            "+",
            "Ltechnology/cariad/cat/genx/GenXError;",
            ">;>;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->$vehicleInformation:Ljava/util/List;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->$continuation:Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->invoke()V

    sget-object p0, Llx0/b0;->a:Llx0/b0;

    return-object p0
.end method

.method public final invoke()V
    .locals 27

    move-object/from16 v0, p0

    .line 2
    new-instance v1, Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-direct {v1}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    .line 3
    iget-object v2, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    invoke-static {v2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getVehiclesLock$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/util/concurrent/locks/ReentrantLock;

    move-result-object v2

    iget-object v3, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    invoke-interface {v2}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 4
    :try_start_0
    invoke-static {v3}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getVehicles$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/util/Map;

    move-result-object v3

    invoke-static {v3}, Lmx0/x;->u(Ljava/util/Map;)Ljava/util/Map;

    move-result-object v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 5
    invoke-interface {v2}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 6
    new-instance v2, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v2}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 7
    iget-object v4, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->$vehicleInformation:Ljava/util/List;

    check-cast v4, Ljava/lang/Iterable;

    iget-object v13, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 8
    new-instance v5, Ljava/util/ArrayList;

    const/16 v6, 0xa

    invoke-static {v4, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v6

    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 9
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    sget-object v16, Lt51/f;->a:Lt51/f;

    const-string v7, "getName(...)"

    const-string v8, "GenX"

    const/4 v9, 0x0

    if-eqz v6, :cond_c

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    .line 10
    check-cast v6, Ltechnology/cariad/cat/genx/Vehicle$Information;

    .line 11
    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getVin()Ljava/lang/String;

    move-result-object v10

    invoke-interface {v3, v10}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 12
    sget-object v23, Llx0/b0;->a:Llx0/b0;

    if-eqz v10, :cond_8

    .line 13
    new-instance v11, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$1;

    invoke-direct {v11, v6}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$1;-><init>(Ltechnology/cariad/cat/genx/Vehicle$Information;)V

    .line 14
    new-instance v14, Lt51/j;

    .line 15
    invoke-static {v13}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v19

    .line 16
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v20

    .line 17
    const-string v15, "GenX"

    const/16 v18, 0x0

    move-object/from16 v17, v11

    invoke-direct/range {v14 .. v20}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 18
    invoke-static {v14}, Lt51/a;->a(Lt51/j;)V

    .line 19
    invoke-interface {v10}, Ltechnology/cariad/cat/genx/InternalVehicle;->getInnerAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    move-result-object v7

    if-eqz v7, :cond_0

    .line 20
    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getInnerAntennaInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v11

    if-eqz v11, :cond_0

    .line 21
    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getInnerAntennaInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v11

    invoke-interface {v7, v11}, Ltechnology/cariad/cat/genx/InternalVehicleAntenna;->update(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ltechnology/cariad/cat/genx/GenXError;

    move-result-object v7

    goto :goto_1

    :cond_0
    if-eqz v7, :cond_1

    .line 22
    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getInnerAntennaInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v11

    if-nez v11, :cond_1

    .line 23
    sget-object v7, Ltechnology/cariad/cat/genx/Antenna;->INNER:Ltechnology/cariad/cat/genx/Antenna;

    invoke-interface {v10, v7}, Ltechnology/cariad/cat/genx/InternalVehicle;->removeAntenna(Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/GenXError;

    move-result-object v7

    goto :goto_1

    :cond_1
    if-nez v7, :cond_2

    .line 24
    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getInnerAntennaInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v7

    if-eqz v7, :cond_2

    .line 25
    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getInnerAntennaInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v18

    .line 26
    invoke-static {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getCredentialStore$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ltechnology/cariad/cat/genx/crypto/CredentialStore;

    move-result-object v20

    const/16 v21, 0x2

    const/16 v22, 0x0

    const/16 v19, 0x0

    move-object/from16 v17, v10

    .line 27
    invoke-static/range {v17 .. v22}, Ltechnology/cariad/cat/genx/InternalVehicle;->addAntenna$default(Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/crypto/CredentialStore;ILjava/lang/Object;)Ltechnology/cariad/cat/genx/GenXError;

    move-result-object v7

    goto :goto_1

    :cond_2
    move-object v7, v9

    .line 28
    :goto_1
    invoke-interface {v10}, Ltechnology/cariad/cat/genx/InternalVehicle;->getOuterAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;

    move-result-object v11

    if-eqz v11, :cond_3

    .line 29
    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getOuterAntennaInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v12

    if-eqz v12, :cond_3

    .line 30
    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getOuterAntennaInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v9

    invoke-interface {v11, v9}, Ltechnology/cariad/cat/genx/InternalVehicleAntenna;->update(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ltechnology/cariad/cat/genx/GenXError;

    move-result-object v9

    goto :goto_2

    :cond_3
    if-eqz v11, :cond_4

    .line 31
    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getOuterAntennaInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v12

    if-nez v12, :cond_4

    .line 32
    sget-object v9, Ltechnology/cariad/cat/genx/Antenna;->OUTER:Ltechnology/cariad/cat/genx/Antenna;

    invoke-interface {v10, v9}, Ltechnology/cariad/cat/genx/InternalVehicle;->removeAntenna(Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/GenXError;

    move-result-object v9

    goto :goto_2

    :cond_4
    if-nez v11, :cond_5

    .line 33
    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getOuterAntennaInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v11

    if-eqz v11, :cond_5

    .line 34
    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getOuterAntennaInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v9

    .line 35
    invoke-static {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getLinkedParametersForOuterAntennaConnections$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    move-result-object v11

    .line 36
    invoke-static {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getCredentialStore$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ltechnology/cariad/cat/genx/crypto/CredentialStore;

    move-result-object v12

    .line 37
    invoke-interface {v10, v9, v11, v12}, Ltechnology/cariad/cat/genx/InternalVehicle;->addAntenna(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/crypto/CredentialStore;)Ltechnology/cariad/cat/genx/GenXError;

    move-result-object v9

    :cond_5
    :goto_2
    if-eqz v7, :cond_6

    .line 38
    new-instance v9, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$2;

    invoke-direct {v9, v10, v6}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$2;-><init>(Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/Vehicle$Information;)V

    .line 39
    invoke-static {v13, v8, v7, v9}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 40
    invoke-virtual {v1, v7}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    move-result v6

    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v23

    :goto_3
    move-object/from16 v25, v3

    move-object/from16 v21, v4

    move-object v3, v5

    :goto_4
    move-object/from16 v4, v23

    goto/16 :goto_7

    :cond_6
    if-eqz v9, :cond_7

    .line 41
    new-instance v7, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$3;

    invoke-direct {v7, v10, v6}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$3;-><init>(Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/Vehicle$Information;)V

    .line 42
    invoke-static {v13, v8, v9, v7}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 43
    invoke-virtual {v1, v9}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    move-result v6

    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v23

    goto :goto_3

    .line 44
    :cond_7
    invoke-interface {v10}, Ltechnology/cariad/cat/genx/Vehicle;->getVin()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v2, v6, v10}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_3

    .line 45
    :cond_8
    new-instance v10, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$4;

    invoke-direct {v10, v6}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$4;-><init>(Ltechnology/cariad/cat/genx/Vehicle$Information;)V

    .line 46
    new-instance v14, Lt51/j;

    .line 47
    invoke-static {v13}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v19

    .line 48
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v20

    .line 49
    const-string v15, "GenX"

    const/16 v18, 0x0

    move-object/from16 v17, v10

    invoke-direct/range {v14 .. v20}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 50
    invoke-static {v14}, Lt51/a;->a(Lt51/j;)V

    .line 51
    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getInnerAntennaInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v7

    if-eqz v7, :cond_9

    move-object v10, v6

    .line 52
    invoke-static {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getCredentialStore$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ltechnology/cariad/cat/genx/crypto/CredentialStore;

    move-result-object v6

    move-object v11, v7

    .line 53
    invoke-static {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getContext$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Landroid/content/Context;

    move-result-object v7

    .line 54
    invoke-virtual {v11}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    move-result-object v12

    invoke-virtual {v12}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getVin()Ljava/lang/String;

    move-result-object v12

    move-object v14, v9

    .line 55
    invoke-virtual {v11}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getLocalKeyPair()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    move-result-object v9

    move-object v15, v10

    .line 56
    invoke-virtual {v11}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getRemoteCredentials()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    move-result-object v10

    move-object/from16 v16, v11

    .line 57
    invoke-virtual/range {v16 .. v16}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMajor-Mh2AYeg()S

    move-result v11

    .line 58
    invoke-virtual/range {v16 .. v16}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMinor-Mh2AYeg()S

    move-result v16

    .line 59
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getDeviceInformation()Ltechnology/cariad/cat/genx/DeviceInformation;

    move-result-object v17

    move-object/from16 v18, v14

    .line 60
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    move-result-object v14

    move-object/from16 v19, v15

    .line 61
    new-instance v15, Ljava/lang/ref/WeakReference;

    invoke-direct {v15, v13}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 62
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isWifiEnabled()Lyy0/a2;

    move-result-object v20

    invoke-interface/range {v20 .. v20}, Lyy0/a2;->getValue()Ljava/lang/Object;

    move-result-object v20

    check-cast v20, Ljava/lang/Boolean;

    invoke-virtual/range {v20 .. v20}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v20

    .line 63
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isBleEnabled()Lyy0/a2;

    move-result-object v21

    invoke-interface/range {v21 .. v21}, Lyy0/a2;->getValue()Ljava/lang/Object;

    move-result-object v21

    check-cast v21, Ljava/lang/Boolean;

    invoke-virtual/range {v21 .. v21}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v21

    move-object/from16 v22, v5

    .line 64
    new-instance v5, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Inner;

    move-object/from16 v24, v19

    const/16 v19, 0x0

    move/from16 v18, v21

    move-object/from16 v21, v4

    move-object v4, v8

    move-object v8, v12

    move/from16 v12, v16

    move-object/from16 v16, v13

    move-object/from16 v13, v17

    move/from16 v17, v18

    move-object/from16 v25, v3

    move/from16 v18, v20

    move-object/from16 v3, v22

    invoke-direct/range {v5 .. v19}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Inner;-><init>(Ltechnology/cariad/cat/genx/crypto/CredentialStore;Landroid/content/Context;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SSLtechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/GenXDispatcher;Ljava/lang/ref/WeakReference;Lvy0/b0;ZZLkotlin/jvm/internal/g;)V

    move-object/from16 v13, v16

    move-object/from16 v22, v5

    goto :goto_5

    :cond_9
    move-object/from16 v25, v3

    move-object/from16 v21, v4

    move-object v3, v5

    move-object/from16 v24, v6

    move-object v4, v8

    const/16 v22, 0x0

    .line 65
    :goto_5
    invoke-virtual/range {v24 .. v24}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getOuterAntennaInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v5

    if-eqz v5, :cond_a

    move-object v6, v5

    .line 66
    new-instance v5, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer;

    move-object v7, v6

    .line 67
    invoke-static {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getCredentialStore$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ltechnology/cariad/cat/genx/crypto/CredentialStore;

    move-result-object v6

    move-object v8, v7

    .line 68
    invoke-static {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getContext$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Landroid/content/Context;

    move-result-object v7

    .line 69
    invoke-virtual {v8}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    move-result-object v9

    invoke-virtual {v9}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getVin()Ljava/lang/String;

    move-result-object v9

    move-object v10, v8

    move-object v8, v9

    .line 70
    invoke-virtual {v10}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getLocalKeyPair()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    move-result-object v9

    move-object v11, v10

    .line 71
    invoke-virtual {v11}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getRemoteCredentials()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    move-result-object v10

    move-object v12, v11

    .line 72
    invoke-virtual {v12}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMajor-Mh2AYeg()S

    move-result v11

    .line 73
    invoke-virtual {v12}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMinor-Mh2AYeg()S

    move-result v12

    .line 74
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getDeviceInformation()Ltechnology/cariad/cat/genx/DeviceInformation;

    move-result-object v14

    move-object v15, v14

    .line 75
    invoke-static {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getLinkedParametersForOuterAntennaConnections$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    move-result-object v14

    move-object/from16 v16, v15

    .line 76
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    move-result-object v15

    move-object/from16 v17, v5

    .line 77
    new-instance v5, Ljava/lang/ref/WeakReference;

    invoke-direct {v5, v13}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 78
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isBleEnabled()Lyy0/a2;

    move-result-object v18

    invoke-interface/range {v18 .. v18}, Lyy0/a2;->getValue()Ljava/lang/Object;

    move-result-object v18

    check-cast v18, Ljava/lang/Boolean;

    invoke-virtual/range {v18 .. v18}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v18

    const/16 v19, 0x0

    move-object/from16 v26, v16

    move-object/from16 v16, v5

    move-object/from16 v5, v17

    move-object/from16 v17, v13

    move-object/from16 v13, v26

    .line 79
    invoke-direct/range {v5 .. v19}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer;-><init>(Ltechnology/cariad/cat/genx/crypto/CredentialStore;Landroid/content/Context;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SSLtechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/GenXDispatcher;Ljava/lang/ref/WeakReference;Lvy0/b0;ZLkotlin/jvm/internal/g;)V

    move-object/from16 v13, v17

    move-object/from16 v17, v5

    move-object/from16 v8, v17

    goto :goto_6

    :cond_a
    const/4 v8, 0x0

    .line 80
    :goto_6
    invoke-virtual/range {v24 .. v24}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getVin()Ljava/lang/String;

    move-result-object v6

    .line 81
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    move-result-object v9

    .line 82
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getDeviceInformation()Ltechnology/cariad/cat/genx/DeviceInformation;

    move-result-object v10

    .line 83
    invoke-static {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getContext$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Landroid/content/Context;

    move-result-object v11

    .line 84
    new-instance v12, Ljava/lang/ref/WeakReference;

    invoke-direct {v12, v13}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 85
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isWifiEnabled()Lyy0/a2;

    move-result-object v5

    invoke-interface {v5}, Lyy0/a2;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Boolean;

    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v15

    .line 86
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isBleEnabled()Lyy0/a2;

    move-result-object v5

    invoke-interface {v5}, Lyy0/a2;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Boolean;

    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v14

    .line 87
    new-instance v5, Ltechnology/cariad/cat/genx/VehicleImpl;

    move-object/from16 v7, v22

    invoke-direct/range {v5 .. v15}, Ltechnology/cariad/cat/genx/VehicleImpl;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;Ltechnology/cariad/cat/genx/GenXDispatcher;Ltechnology/cariad/cat/genx/DeviceInformation;Landroid/content/Context;Ljava/lang/ref/WeakReference;Lvy0/b0;ZZ)V

    .line 88
    new-instance v6, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$registrationError$1;

    invoke-direct {v6, v13, v5}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$registrationError$1;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/VehicleImpl;)V

    invoke-static {v6}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    move-result-object v6

    if-nez v6, :cond_b

    .line 89
    invoke-virtual/range {v24 .. v24}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getVin()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v4, v5}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto/16 :goto_4

    .line 90
    :cond_b
    new-instance v5, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$5;

    move-object/from16 v15, v24

    invoke-direct {v5, v15}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$5;-><init>(Ltechnology/cariad/cat/genx/Vehicle$Information;)V

    .line 91
    invoke-static {v13, v4, v6, v5}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 92
    invoke-virtual {v1, v6}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    move-result v4

    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v23

    goto/16 :goto_4

    .line 93
    :goto_7
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object v5, v3

    move-object/from16 v4, v21

    move-object/from16 v3, v25

    goto/16 :goto_0

    :cond_c
    move-object/from16 v25, v3

    move-object v4, v8

    .line 94
    invoke-virtual {v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->isEmpty()Z

    move-result v3

    if-nez v3, :cond_d

    .line 95
    iget-object v3, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    new-instance v5, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$2;

    invoke-direct {v5, v1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$2;-><init>(Ljava/util/concurrent/CopyOnWriteArrayList;)V

    const/4 v14, 0x0

    .line 96
    invoke-static {v3, v4, v14, v5}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 97
    :cond_d
    iget-object v3, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    invoke-static {v3}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getVehiclesLock$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/util/concurrent/locks/ReentrantLock;

    move-result-object v3

    iget-object v5, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    invoke-interface {v3}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 98
    :try_start_1
    invoke-static {v5, v2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$setVehicles$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/util/Map;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 99
    invoke-interface {v3}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 100
    invoke-virtual {v2}, Ljava/util/concurrent/ConcurrentHashMap;->keySet()Ljava/util/Set;

    move-result-object v2

    const-string v3, "<get-keys>(...)"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Ljava/lang/Iterable;

    .line 101
    invoke-static/range {v25 .. v25}, Lmx0/x;->w(Ljava/util/Map;)Ljava/util/LinkedHashMap;

    move-result-object v3

    invoke-virtual {v3}, Ljava/util/LinkedHashMap;->keySet()Ljava/util/Set;

    move-result-object v5

    check-cast v5, Ljava/util/Collection;

    const-string v6, "<this>"

    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 102
    invoke-static {v2}, Lmx0/q;->B(Ljava/lang/Iterable;)Ljava/util/Collection;

    move-result-object v2

    invoke-interface {v5, v2}, Ljava/util/Collection;->removeAll(Ljava/util/Collection;)Z

    .line 103
    invoke-static {v3}, Lmx0/x;->o(Ljava/util/LinkedHashMap;)Ljava/util/Map;

    move-result-object v2

    .line 104
    iget-object v3, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    new-instance v11, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$4;

    invoke-direct {v11, v2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$4;-><init>(Ljava/util/Map;)V

    .line 105
    new-instance v8, Lt51/j;

    .line 106
    invoke-static {v3}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v13

    .line 107
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v14

    .line 108
    const-string v9, "GenX"

    sget-object v10, Lt51/d;->a:Lt51/d;

    const/4 v12, 0x0

    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 109
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 110
    iget-object v3, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 111
    invoke-interface {v2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_e
    :goto_8
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_f

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/Map$Entry;

    .line 112
    invoke-interface {v5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/String;

    .line 113
    new-instance v6, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$5$1;

    invoke-direct {v6, v5}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$5$1;-><init>(Ljava/lang/String;)V

    .line 114
    new-instance v14, Lt51/j;

    .line 115
    invoke-static {v3}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v19

    .line 116
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v20

    .line 117
    const-string v15, "GenX"

    const/16 v18, 0x0

    move-object/from16 v17, v6

    invoke-direct/range {v14 .. v20}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 118
    invoke-static {v14}, Lt51/a;->a(Lt51/j;)V

    .line 119
    invoke-static {v3, v5}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$unregisterVehicleNonDispatched(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;)Ltechnology/cariad/cat/genx/GenXError;

    move-result-object v6

    if-eqz v6, :cond_e

    .line 120
    new-instance v8, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$5$2$1;

    invoke-direct {v8, v5}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$5$2$1;-><init>(Ljava/lang/String;)V

    .line 121
    invoke-static {v3, v4, v6, v8}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 122
    invoke-virtual {v1, v6}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_8

    .line 123
    :cond_f
    iget-object v0, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->$continuation:Lkotlin/coroutines/Continuation;

    invoke-static {v1}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    return-void

    :catchall_0
    move-exception v0

    .line 124
    invoke-interface {v3}, Ljava/util/concurrent/locks/Lock;->unlock()V

    throw v0

    :catchall_1
    move-exception v0

    .line 125
    invoke-interface {v2}, Ljava/util/concurrent/locks/Lock;->unlock()V

    throw v0
.end method
