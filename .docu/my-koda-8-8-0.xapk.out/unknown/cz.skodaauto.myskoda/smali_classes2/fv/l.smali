.class public final enum Lfv/l;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Executor;


# static fields
.field public static final enum d:Lfv/l;

.field public static final synthetic e:[Lfv/l;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lfv/l;

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
    sput-object v0, Lfv/l;->d:Lfv/l;

    .line 10
    .line 11
    filled-new-array {v0}, [Lfv/l;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lfv/l;->e:[Lfv/l;

    .line 16
    .line 17
    return-void
.end method

.method public static values()[Lfv/l;
    .locals 1

    .line 1
    sget-object v0, Lfv/l;->e:[Lfv/l;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lfv/l;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lfv/l;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final execute(Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    invoke-static {}, Lfv/e;->a()Lfv/e;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lfv/e;->a:Lbp/c;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 8
    .line 9
    .line 10
    return-void
.end method
