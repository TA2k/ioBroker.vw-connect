.class public final enum Lbl0/g;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lbl0/g;

.field public static final enum f:Lbl0/g;

.field public static final enum g:Lbl0/g;

.field public static final enum h:Lbl0/g;

.field public static final synthetic i:[Lbl0/g;

.field public static final synthetic j:Lsx0/b;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lbl0/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0x16

    .line 5
    .line 6
    const-string v3, "Value22"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lbl0/g;-><init>(Ljava/lang/String;II)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lbl0/g;->e:Lbl0/g;

    .line 12
    .line 13
    new-instance v1, Lbl0/g;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const/16 v3, 0x32

    .line 17
    .line 18
    const-string v4, "Value50"

    .line 19
    .line 20
    invoke-direct {v1, v4, v2, v3}, Lbl0/g;-><init>(Ljava/lang/String;II)V

    .line 21
    .line 22
    .line 23
    sput-object v1, Lbl0/g;->f:Lbl0/g;

    .line 24
    .line 25
    new-instance v2, Lbl0/g;

    .line 26
    .line 27
    const/4 v3, 0x2

    .line 28
    const/16 v4, 0x4b

    .line 29
    .line 30
    const-string v5, "Value75"

    .line 31
    .line 32
    invoke-direct {v2, v5, v3, v4}, Lbl0/g;-><init>(Ljava/lang/String;II)V

    .line 33
    .line 34
    .line 35
    new-instance v3, Lbl0/g;

    .line 36
    .line 37
    const/4 v4, 0x3

    .line 38
    const/16 v5, 0x64

    .line 39
    .line 40
    const-string v6, "Value100"

    .line 41
    .line 42
    invoke-direct {v3, v6, v4, v5}, Lbl0/g;-><init>(Ljava/lang/String;II)V

    .line 43
    .line 44
    .line 45
    sput-object v3, Lbl0/g;->g:Lbl0/g;

    .line 46
    .line 47
    new-instance v4, Lbl0/g;

    .line 48
    .line 49
    const/4 v5, 0x4

    .line 50
    const/16 v6, 0x96

    .line 51
    .line 52
    const-string v7, "Value150"

    .line 53
    .line 54
    invoke-direct {v4, v7, v5, v6}, Lbl0/g;-><init>(Ljava/lang/String;II)V

    .line 55
    .line 56
    .line 57
    sput-object v4, Lbl0/g;->h:Lbl0/g;

    .line 58
    .line 59
    filled-new-array {v0, v1, v2, v3, v4}, [Lbl0/g;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    sput-object v0, Lbl0/g;->i:[Lbl0/g;

    .line 64
    .line 65
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    sput-object v0, Lbl0/g;->j:Lsx0/b;

    .line 70
    .line 71
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lbl0/g;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lbl0/g;
    .locals 1

    .line 1
    const-class v0, Lbl0/g;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lbl0/g;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lbl0/g;
    .locals 1

    .line 1
    sget-object v0, Lbl0/g;->i:[Lbl0/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lbl0/g;

    .line 8
    .line 9
    return-object v0
.end method
