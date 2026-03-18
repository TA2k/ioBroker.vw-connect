.class public final Ln00/h;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lbd0/c;

.field public final i:Ltr0/b;

.field public final j:Ll00/i;


# direct methods
.method public constructor <init>(Lbd0/c;Ltr0/b;Ll00/i;)V
    .locals 2

    .line 1
    new-instance v0, Ln00/g;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ln00/g;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Ln00/h;->h:Lbd0/c;

    .line 12
    .line 13
    iput-object p2, p0, Ln00/h;->i:Ltr0/b;

    .line 14
    .line 15
    iput-object p3, p0, Ln00/h;->j:Ll00/i;

    .line 16
    .line 17
    new-instance p1, Ln00/f;

    .line 18
    .line 19
    const/4 p2, 0x0

    .line 20
    const/4 p3, 0x0

    .line 21
    invoke-direct {p1, p0, p2, p3}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method
