.class public abstract Lpx0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lpx0/e;


# instance fields
.field private final key:Lpx0/f;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lpx0/f;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lpx0/f;)V
    .locals 1

    .line 1
    const-string v0, "key"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lpx0/a;->key:Lpx0/f;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public bridge fold(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<R:",
            "Ljava/lang/Object;",
            ">(TR;",
            "Lay0/n;",
            ")TR;"
        }
    .end annotation

    .line 1
    invoke-static {p0, p1, p2}, Ljp/de;->a(Lpx0/e;Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public bridge get(Lpx0/f;)Lpx0/e;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E::",
            "Lpx0/e;",
            ">(",
            "Lpx0/f;",
            ")TE;"
        }
    .end annotation

    .line 1
    invoke-static {p0, p1}, Ljp/de;->b(Lpx0/e;Lpx0/f;)Lpx0/e;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public getKey()Lpx0/f;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lpx0/f;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lpx0/a;->key:Lpx0/f;

    .line 2
    .line 3
    return-object p0
.end method

.method public bridge minusKey(Lpx0/f;)Lpx0/g;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lpx0/f;",
            ")",
            "Lpx0/g;"
        }
    .end annotation

    .line 1
    invoke-static {p0, p1}, Ljp/de;->c(Lpx0/e;Lpx0/f;)Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public bridge plus(Lpx0/g;)Lpx0/g;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ljp/de;->d(Lpx0/e;Lpx0/g;)Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
