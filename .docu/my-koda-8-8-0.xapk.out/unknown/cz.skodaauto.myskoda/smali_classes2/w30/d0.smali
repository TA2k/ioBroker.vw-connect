.class public final Lw30/d0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lu30/n;


# direct methods
.method public constructor <init>(Ltr0/b;Lu30/n;)V
    .locals 2

    .line 1
    new-instance v0, Lw30/c0;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    invoke-direct {v0, v1, v1}, Lw30/c0;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lw30/d0;->h:Ltr0/b;

    .line 12
    .line 13
    iput-object p2, p0, Lw30/d0;->i:Lu30/n;

    .line 14
    .line 15
    new-instance p1, Lvo0/e;

    .line 16
    .line 17
    const/4 p2, 0x0

    .line 18
    const/4 v0, 0x4

    .line 19
    invoke-direct {p1, p0, p2, v0}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method
