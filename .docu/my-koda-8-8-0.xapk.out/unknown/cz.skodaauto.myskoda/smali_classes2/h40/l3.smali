.class public final enum Lh40/l3;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lh40/l3;

.field public static final synthetic f:[Lh40/l3;

.field public static final synthetic g:Lsx0/b;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lh40/l3;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const v2, 0x7f120cb3

    .line 5
    .line 6
    .line 7
    const-string v3, "AllDraws"

    .line 8
    .line 9
    invoke-direct {v0, v3, v1, v2}, Lh40/l3;-><init>(Ljava/lang/String;II)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lh40/l3;->e:Lh40/l3;

    .line 13
    .line 14
    new-instance v1, Lh40/l3;

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    const v3, 0x7f120cb4

    .line 18
    .line 19
    .line 20
    const-string v4, "MyDraws"

    .line 21
    .line 22
    invoke-direct {v1, v4, v2, v3}, Lh40/l3;-><init>(Ljava/lang/String;II)V

    .line 23
    .line 24
    .line 25
    filled-new-array {v0, v1}, [Lh40/l3;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sput-object v0, Lh40/l3;->f:[Lh40/l3;

    .line 30
    .line 31
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lh40/l3;->g:Lsx0/b;

    .line 36
    .line 37
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lh40/l3;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lh40/l3;
    .locals 1

    .line 1
    const-class v0, Lh40/l3;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lh40/l3;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lh40/l3;
    .locals 1

    .line 1
    sget-object v0, Lh40/l3;->f:[Lh40/l3;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lh40/l3;

    .line 8
    .line 9
    return-object v0
.end method
