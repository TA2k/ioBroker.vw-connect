.class public final enum Llp/sb;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llp/a0;


# static fields
.field public static final enum e:Llp/sb;

.field public static final enum f:Llp/sb;

.field public static final synthetic g:[Llp/sb;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Llp/sb;

    .line 2
    .line 3
    const-string v1, "TYPE_UNKNOWN"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Llp/sb;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Llp/sb;

    .line 10
    .line 11
    const-string v2, "TYPE_THIN"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3, v3}, Llp/sb;-><init>(Ljava/lang/String;II)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Llp/sb;->e:Llp/sb;

    .line 18
    .line 19
    new-instance v2, Llp/sb;

    .line 20
    .line 21
    const-string v3, "TYPE_THICK"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4, v4}, Llp/sb;-><init>(Ljava/lang/String;II)V

    .line 25
    .line 26
    .line 27
    sput-object v2, Llp/sb;->f:Llp/sb;

    .line 28
    .line 29
    new-instance v3, Llp/sb;

    .line 30
    .line 31
    const-string v4, "TYPE_GMV"

    .line 32
    .line 33
    const/4 v5, 0x3

    .line 34
    invoke-direct {v3, v4, v5, v5}, Llp/sb;-><init>(Ljava/lang/String;II)V

    .line 35
    .line 36
    .line 37
    filled-new-array {v0, v1, v2, v3}, [Llp/sb;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Llp/sb;->g:[Llp/sb;

    .line 42
    .line 43
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Llp/sb;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static values()[Llp/sb;
    .locals 1

    .line 1
    sget-object v0, Llp/sb;->g:[Llp/sb;

    .line 2
    .line 3
    invoke-virtual {v0}, [Llp/sb;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Llp/sb;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final h()I
    .locals 0

    .line 1
    iget p0, p0, Llp/sb;->d:I

    .line 2
    .line 3
    return p0
.end method
