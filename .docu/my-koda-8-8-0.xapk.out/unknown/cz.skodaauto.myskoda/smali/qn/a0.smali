.class public final enum Lqn/a0;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lqn/a0;

.field public static final synthetic e:[Lqn/a0;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lqn/a0;

    .line 2
    .line 3
    const-string v1, "NOT_SET"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lqn/a0;

    .line 10
    .line 11
    const-string v3, "EVENT_OVERRIDE"

    .line 12
    .line 13
    const/4 v4, 0x1

    .line 14
    invoke-direct {v1, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lqn/a0;->d:Lqn/a0;

    .line 18
    .line 19
    filled-new-array {v0, v1}, [Lqn/a0;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    sput-object v3, Lqn/a0;->e:[Lqn/a0;

    .line 24
    .line 25
    new-instance v3, Landroid/util/SparseArray;

    .line 26
    .line 27
    invoke-direct {v3}, Landroid/util/SparseArray;-><init>()V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v3, v2, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    const/4 v0, 0x5

    .line 34
    invoke-virtual {v3, v0, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lqn/a0;
    .locals 1

    .line 1
    const-class v0, Lqn/a0;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqn/a0;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lqn/a0;
    .locals 1

    .line 1
    sget-object v0, Lqn/a0;->e:[Lqn/a0;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lqn/a0;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lqn/a0;

    .line 8
    .line 9
    return-object v0
.end method
