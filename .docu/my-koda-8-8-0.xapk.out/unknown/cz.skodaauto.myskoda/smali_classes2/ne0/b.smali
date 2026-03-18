.class public final enum Lne0/b;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lne0/b;

.field public static final enum f:Lne0/b;

.field public static final enum g:Lne0/b;

.field public static final synthetic h:[Lne0/b;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lne0/b;

    .line 2
    .line 3
    const-string v1, "General"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    invoke-direct {v0, v1, v2, v3}, Lne0/b;-><init>(Ljava/lang/String;II)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lne0/b;->e:Lne0/b;

    .line 11
    .line 12
    new-instance v1, Lne0/b;

    .line 13
    .line 14
    const-string v2, "Timeout"

    .line 15
    .line 16
    const/4 v4, 0x2

    .line 17
    invoke-direct {v1, v2, v3, v4}, Lne0/b;-><init>(Ljava/lang/String;II)V

    .line 18
    .line 19
    .line 20
    sput-object v1, Lne0/b;->f:Lne0/b;

    .line 21
    .line 22
    new-instance v2, Lne0/b;

    .line 23
    .line 24
    const-string v3, "MissingInternet"

    .line 25
    .line 26
    const/4 v5, 0x3

    .line 27
    invoke-direct {v2, v3, v4, v5}, Lne0/b;-><init>(Ljava/lang/String;II)V

    .line 28
    .line 29
    .line 30
    sput-object v2, Lne0/b;->g:Lne0/b;

    .line 31
    .line 32
    filled-new-array {v0, v1, v2}, [Lne0/b;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    sput-object v0, Lne0/b;->h:[Lne0/b;

    .line 37
    .line 38
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lne0/b;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lne0/b;
    .locals 1

    .line 1
    const-class v0, Lne0/b;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lne0/b;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lne0/b;
    .locals 1

    .line 1
    sget-object v0, Lne0/b;->h:[Lne0/b;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lne0/b;

    .line 8
    .line 9
    return-object v0
.end method
