.class public final Lcom/salesforce/marketingcloud/InitializationStatus;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/InitializationStatus$a;,
        Lcom/salesforce/marketingcloud/InitializationStatus$b;,
        Lcom/salesforce/marketingcloud/InitializationStatus$Status;
    }
.end annotation


# static fields
.field public static final Companion:Lcom/salesforce/marketingcloud/InitializationStatus$b;


# instance fields
.field public final encryptionChanged:Z

.field public final initializedComponents:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field public final isUsable:Z

.field public final locationsError:Z

.field public final messagingPermissionError:Z

.field public final playServicesMessage:Ljava/lang/String;

.field public final playServicesStatus:I

.field public final proximityError:Z

.field public final sslProviderEnablementError:Z

.field public final status:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

.field public final storageError:Z

.field public final unrecoverableException:Ljava/lang/Throwable;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/InitializationStatus$b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/InitializationStatus$b;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/InitializationStatus;->Companion:Lcom/salesforce/marketingcloud/InitializationStatus$b;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/InitializationStatus$Status;Ljava/lang/Throwable;ZILjava/lang/String;ZZZZZLjava/util/List;Z)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/InitializationStatus$Status;",
            "Ljava/lang/Throwable;",
            "ZI",
            "Ljava/lang/String;",
            "ZZZZZ",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;Z)V"
        }
    .end annotation

    const-string v0, "status"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "initializedComponents"

    invoke-static {p11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->status:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->unrecoverableException:Ljava/lang/Throwable;

    .line 4
    iput-boolean p3, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->locationsError:Z

    .line 5
    iput p4, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->playServicesStatus:I

    .line 6
    iput-object p5, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->playServicesMessage:Ljava/lang/String;

    .line 7
    iput-boolean p6, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->encryptionChanged:Z

    .line 8
    iput-boolean p7, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->storageError:Z

    .line 9
    iput-boolean p8, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->proximityError:Z

    .line 10
    iput-boolean p9, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->messagingPermissionError:Z

    .line 11
    iput-boolean p10, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->sslProviderEnablementError:Z

    .line 12
    iput-object p11, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->initializedComponents:Ljava/util/List;

    .line 13
    iput-boolean p12, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->isUsable:Z

    return-void
.end method

.method public synthetic constructor <init>(Lcom/salesforce/marketingcloud/InitializationStatus$Status;Ljava/lang/Throwable;ZILjava/lang/String;ZZZZZLjava/util/List;ZILkotlin/jvm/internal/g;)V
    .locals 14

    move/from16 v0, p13

    and-int/lit16 v0, v0, 0x800

    if-eqz v0, :cond_1

    .line 14
    sget-object v0, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->FAILED:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    if-eq p1, v0, :cond_0

    const/4 v0, 0x1

    :goto_0
    move-object v1, p0

    move-object v2, p1

    move-object/from16 v3, p2

    move/from16 v4, p3

    move/from16 v5, p4

    move-object/from16 v6, p5

    move/from16 v7, p6

    move/from16 v8, p7

    move/from16 v9, p8

    move/from16 v10, p9

    move/from16 v11, p10

    move-object/from16 v12, p11

    move v13, v0

    goto :goto_1

    :cond_0
    const/4 v0, 0x0

    goto :goto_0

    :cond_1
    move-object v1, p0

    move-object v2, p1

    move-object/from16 v3, p2

    move/from16 v4, p3

    move/from16 v5, p4

    move-object/from16 v6, p5

    move/from16 v7, p6

    move/from16 v8, p7

    move/from16 v9, p8

    move/from16 v10, p9

    move/from16 v11, p10

    move-object/from16 v12, p11

    move/from16 v13, p12

    .line 15
    :goto_1
    invoke-direct/range {v1 .. v13}, Lcom/salesforce/marketingcloud/InitializationStatus;-><init>(Lcom/salesforce/marketingcloud/InitializationStatus$Status;Ljava/lang/Throwable;ZILjava/lang/String;ZZZZZLjava/util/List;Z)V

    return-void
.end method


# virtual methods
.method public final encryptionChanged()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->encryptionChanged:Z

    .line 2
    .line 3
    return p0
.end method

.method public final initializedComponents()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->initializedComponents:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final isUsable()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->isUsable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final locationsError()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->locationsError:Z

    .line 2
    .line 3
    return p0
.end method

.method public final messagingPermissionError()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->messagingPermissionError:Z

    .line 2
    .line 3
    return p0
.end method

.method public final playServicesMessage()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->playServicesMessage:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final playServicesStatus()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->playServicesStatus:I

    .line 2
    .line 3
    return p0
.end method

.method public final proximityError()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->proximityError:Z

    .line 2
    .line 3
    return p0
.end method

.method public final sslProviderEnablementError()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->sslProviderEnablementError:Z

    .line 2
    .line 3
    return p0
.end method

.method public final status()Lcom/salesforce/marketingcloud/InitializationStatus$Status;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->status:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 2
    .line 3
    return-object p0
.end method

.method public final storageError()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->storageError:Z

    .line 2
    .line 3
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 13

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->status:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->unrecoverableException:Ljava/lang/Throwable;

    .line 4
    .line 5
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->locationsError:Z

    .line 6
    .line 7
    iget v3, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->playServicesStatus:I

    .line 8
    .line 9
    iget-object v4, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->playServicesMessage:Ljava/lang/String;

    .line 10
    .line 11
    iget-boolean v5, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->encryptionChanged:Z

    .line 12
    .line 13
    iget-boolean v6, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->storageError:Z

    .line 14
    .line 15
    iget-boolean v7, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->proximityError:Z

    .line 16
    .line 17
    iget-boolean v8, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->messagingPermissionError:Z

    .line 18
    .line 19
    iget-boolean v9, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->sslProviderEnablementError:Z

    .line 20
    .line 21
    iget-object v10, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->initializedComponents:Ljava/util/List;

    .line 22
    .line 23
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->isUsable:Z

    .line 24
    .line 25
    new-instance v11, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    const-string v12, "InitializationStatus(status="

    .line 28
    .line 29
    invoke-direct {v11, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ", unrecoverableException="

    .line 36
    .line 37
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v11, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v0, ", locationsError="

    .line 44
    .line 45
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v11, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v0, ", playServicesStatus="

    .line 52
    .line 53
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {v11, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v0, ", playServicesMessage="

    .line 60
    .line 61
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v0, ", encryptionChanged="

    .line 65
    .line 66
    const-string v1, ", storageError="

    .line 67
    .line 68
    invoke-static {v4, v0, v1, v11, v5}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 69
    .line 70
    .line 71
    const-string v0, ", proximityError="

    .line 72
    .line 73
    const-string v1, ", messagingPermissionError="

    .line 74
    .line 75
    invoke-static {v11, v6, v0, v7, v1}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 76
    .line 77
    .line 78
    const-string v0, ", sslProviderEnablementError="

    .line 79
    .line 80
    const-string v1, ", initializedComponents="

    .line 81
    .line 82
    invoke-static {v11, v8, v0, v9, v1}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v11, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    const-string v0, ", isUsable="

    .line 89
    .line 90
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v11, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    const-string p0, ")"

    .line 97
    .line 98
    invoke-virtual {v11, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    return-object p0
.end method

.method public final unrecoverableException()Ljava/lang/Throwable;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus;->unrecoverableException:Ljava/lang/Throwable;

    .line 2
    .line 3
    return-object p0
.end method
