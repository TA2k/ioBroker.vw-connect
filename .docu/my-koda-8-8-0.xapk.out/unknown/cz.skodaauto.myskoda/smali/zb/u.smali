.class public final Lzb/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk1/i;


# static fields
.field public static final d:Lzb/u;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lzb/u;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lzb/u;->d:Lzb/u;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public b(Lt4/c;I[I[I)V
    .locals 5

    .line 1
    const-string p0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length p0, p3

    .line 7
    const/4 p1, 0x0

    .line 8
    move v0, p1

    .line 9
    move v1, v0

    .line 10
    :goto_0
    if-ge p1, p0, :cond_1

    .line 11
    .line 12
    aget v2, p3, p1

    .line 13
    .line 14
    add-int/lit8 v3, v0, 0x1

    .line 15
    .line 16
    array-length v4, p3

    .line 17
    add-int/lit8 v4, v4, -0x1

    .line 18
    .line 19
    if-ne v0, v4, :cond_0

    .line 20
    .line 21
    sub-int v2, p2, v2

    .line 22
    .line 23
    aput v2, p4, v0

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_0
    aput v1, p4, v0

    .line 27
    .line 28
    add-int/2addr v1, v2

    .line 29
    :goto_1
    add-int/lit8 p1, p1, 0x1

    .line 30
    .line 31
    move v0, v3

    .line 32
    goto :goto_0

    .line 33
    :cond_1
    return-void
.end method
