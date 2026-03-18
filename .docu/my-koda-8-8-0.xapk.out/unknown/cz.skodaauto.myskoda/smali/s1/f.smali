.class public abstract Ls1/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ls1/e;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Ls1/f;->a()Ls1/e;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Ls1/f;->a:Ls1/e;

    .line 6
    .line 7
    return-void
.end method

.method public static final a()Ls1/e;
    .locals 2

    .line 1
    new-instance v0, Ls1/d;

    .line 2
    .line 3
    const/16 v1, 0x32

    .line 4
    .line 5
    int-to-float v1, v1

    .line 6
    invoke-direct {v0, v1}, Ls1/d;-><init>(F)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Ls1/e;

    .line 10
    .line 11
    invoke-direct {v1, v0, v0, v0, v0}, Ls1/e;-><init>(Ls1/a;Ls1/a;Ls1/a;Ls1/a;)V

    .line 12
    .line 13
    .line 14
    return-object v1
.end method

.method public static final b(F)Ls1/e;
    .locals 1

    .line 1
    new-instance v0, Ls1/b;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Ls1/b;-><init>(F)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ls1/e;

    .line 7
    .line 8
    invoke-direct {p0, v0, v0, v0, v0}, Ls1/e;-><init>(Ls1/a;Ls1/a;Ls1/a;Ls1/a;)V

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public static final c(FFFF)Ls1/e;
    .locals 2

    .line 1
    new-instance v0, Ls1/e;

    .line 2
    .line 3
    new-instance v1, Ls1/b;

    .line 4
    .line 5
    invoke-direct {v1, p0}, Ls1/b;-><init>(F)V

    .line 6
    .line 7
    .line 8
    new-instance p0, Ls1/b;

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ls1/b;-><init>(F)V

    .line 11
    .line 12
    .line 13
    new-instance p1, Ls1/b;

    .line 14
    .line 15
    invoke-direct {p1, p2}, Ls1/b;-><init>(F)V

    .line 16
    .line 17
    .line 18
    new-instance p2, Ls1/b;

    .line 19
    .line 20
    invoke-direct {p2, p3}, Ls1/b;-><init>(F)V

    .line 21
    .line 22
    .line 23
    invoke-direct {v0, v1, p0, p1, p2}, Ls1/e;-><init>(Ls1/a;Ls1/a;Ls1/a;Ls1/a;)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method

.method public static d(FF)Ls1/e;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    int-to-float v1, v0

    .line 3
    int-to-float v0, v0

    .line 4
    invoke-static {p0, p1, v1, v0}, Ls1/f;->c(FFFF)Ls1/e;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method
