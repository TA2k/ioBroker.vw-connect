.class public final enum Lc7/b;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/glance/appwidget/protobuf/w;


# static fields
.field public static final enum e:Lc7/b;

.field public static final enum f:Lc7/b;

.field public static final enum g:Lc7/b;

.field public static final enum h:Lc7/b;

.field public static final enum i:Lc7/b;

.field public static final synthetic j:[Lc7/b;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Lc7/b;

    .line 2
    .line 3
    const-string v1, "UNKNOWN_DIMENSION_TYPE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lc7/b;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lc7/b;

    .line 10
    .line 11
    const-string v2, "EXACT"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3, v3}, Lc7/b;-><init>(Ljava/lang/String;II)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lc7/b;->e:Lc7/b;

    .line 18
    .line 19
    new-instance v2, Lc7/b;

    .line 20
    .line 21
    const-string v3, "WRAP"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4, v4}, Lc7/b;-><init>(Ljava/lang/String;II)V

    .line 25
    .line 26
    .line 27
    sput-object v2, Lc7/b;->f:Lc7/b;

    .line 28
    .line 29
    new-instance v3, Lc7/b;

    .line 30
    .line 31
    const-string v4, "FILL"

    .line 32
    .line 33
    const/4 v5, 0x3

    .line 34
    invoke-direct {v3, v4, v5, v5}, Lc7/b;-><init>(Ljava/lang/String;II)V

    .line 35
    .line 36
    .line 37
    sput-object v3, Lc7/b;->g:Lc7/b;

    .line 38
    .line 39
    new-instance v4, Lc7/b;

    .line 40
    .line 41
    const-string v5, "EXPAND"

    .line 42
    .line 43
    const/4 v6, 0x4

    .line 44
    invoke-direct {v4, v5, v6, v6}, Lc7/b;-><init>(Ljava/lang/String;II)V

    .line 45
    .line 46
    .line 47
    sput-object v4, Lc7/b;->h:Lc7/b;

    .line 48
    .line 49
    new-instance v5, Lc7/b;

    .line 50
    .line 51
    const/4 v6, 0x5

    .line 52
    const/4 v7, -0x1

    .line 53
    const-string v8, "UNRECOGNIZED"

    .line 54
    .line 55
    invoke-direct {v5, v8, v6, v7}, Lc7/b;-><init>(Ljava/lang/String;II)V

    .line 56
    .line 57
    .line 58
    sput-object v5, Lc7/b;->i:Lc7/b;

    .line 59
    .line 60
    filled-new-array/range {v0 .. v5}, [Lc7/b;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    sput-object v0, Lc7/b;->j:[Lc7/b;

    .line 65
    .line 66
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lc7/b;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lc7/b;
    .locals 1

    .line 1
    const-class v0, Lc7/b;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lc7/b;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lc7/b;
    .locals 1

    .line 1
    sget-object v0, Lc7/b;->j:[Lc7/b;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lc7/b;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lc7/b;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getNumber()I
    .locals 1

    .line 1
    sget-object v0, Lc7/b;->i:Lc7/b;

    .line 2
    .line 3
    if-eq p0, v0, :cond_0

    .line 4
    .line 5
    iget p0, p0, Lc7/b;->d:I

    .line 6
    .line 7
    return p0

    .line 8
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 9
    .line 10
    const-string v0, "Can\'t get the number of an unknown enum value."

    .line 11
    .line 12
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    throw p0
.end method
