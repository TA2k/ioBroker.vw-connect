.class public final enum Lqn/k0;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lqn/k0;

.field public static final synthetic e:[Lqn/k0;


# direct methods
.method static constructor <clinit>()V
    .locals 13

    .line 1
    new-instance v0, Lqn/k0;

    .line 2
    .line 3
    const-string v1, "DEFAULT"

    .line 4
    .line 5
    const/4 v6, 0x0

    .line 6
    invoke-direct {v0, v1, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lqn/k0;->d:Lqn/k0;

    .line 10
    .line 11
    new-instance v1, Lqn/k0;

    .line 12
    .line 13
    const-string v2, "UNMETERED_ONLY"

    .line 14
    .line 15
    const/4 v7, 0x1

    .line 16
    invoke-direct {v1, v2, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    new-instance v2, Lqn/k0;

    .line 20
    .line 21
    const-string v3, "UNMETERED_OR_DAILY"

    .line 22
    .line 23
    const/4 v8, 0x2

    .line 24
    invoke-direct {v2, v3, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    new-instance v3, Lqn/k0;

    .line 28
    .line 29
    const-string v4, "FAST_IF_RADIO_AWAKE"

    .line 30
    .line 31
    const/4 v9, 0x3

    .line 32
    invoke-direct {v3, v4, v9}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 33
    .line 34
    .line 35
    new-instance v4, Lqn/k0;

    .line 36
    .line 37
    const-string v5, "NEVER"

    .line 38
    .line 39
    const/4 v10, 0x4

    .line 40
    invoke-direct {v4, v5, v10}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 41
    .line 42
    .line 43
    new-instance v5, Lqn/k0;

    .line 44
    .line 45
    const-string v11, "UNRECOGNIZED"

    .line 46
    .line 47
    const/4 v12, 0x5

    .line 48
    invoke-direct {v5, v11, v12}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 49
    .line 50
    .line 51
    filled-new-array/range {v0 .. v5}, [Lqn/k0;

    .line 52
    .line 53
    .line 54
    move-result-object v11

    .line 55
    sput-object v11, Lqn/k0;->e:[Lqn/k0;

    .line 56
    .line 57
    new-instance v11, Landroid/util/SparseArray;

    .line 58
    .line 59
    invoke-direct {v11}, Landroid/util/SparseArray;-><init>()V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v11, v6, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v11, v7, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v11, v8, v2}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v11, v9, v3}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v11, v10, v4}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    const/4 v0, -0x1

    .line 78
    invoke-virtual {v11, v0, v5}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lqn/k0;
    .locals 1

    .line 1
    const-class v0, Lqn/k0;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqn/k0;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lqn/k0;
    .locals 1

    .line 1
    sget-object v0, Lqn/k0;->e:[Lqn/k0;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lqn/k0;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lqn/k0;

    .line 8
    .line 9
    return-object v0
.end method
