.class public final enum Ly4/l;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Executor;


# static fields
.field public static final enum d:Ly4/l;

.field public static final synthetic e:[Ly4/l;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ly4/l;

    .line 2
    .line 3
    const-string v1, "INSTANCE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ly4/l;->d:Ly4/l;

    .line 10
    .line 11
    filled-new-array {v0}, [Ly4/l;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Ly4/l;->e:[Ly4/l;

    .line 16
    .line 17
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Ly4/l;
    .locals 1

    .line 1
    const-class v0, Ly4/l;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ly4/l;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ly4/l;
    .locals 1

    .line 1
    sget-object v0, Ly4/l;->e:[Ly4/l;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ly4/l;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ly4/l;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final execute(Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    invoke-interface {p1}, Ljava/lang/Runnable;->run()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "DirectExecutor"

    .line 2
    .line 3
    return-object p0
.end method
