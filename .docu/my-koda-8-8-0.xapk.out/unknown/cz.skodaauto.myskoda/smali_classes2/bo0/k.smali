.class public final Lbo0/k;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lyn0/r;

.field public final j:Lyn0/d;

.field public final k:Lyn0/n;

.field public final l:Lij0/a;

.field public final m:Lqf0/g;

.field public n:Ljava/util/List;

.field public o:Ljava/util/List;

.field public p:Z


# direct methods
.method public constructor <init>(Ltr0/b;Lyn0/r;Lyn0/d;Lyn0/n;Lij0/a;Lqf0/g;)V
    .locals 3

    .line 1
    new-instance v0, Lbo0/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 5
    .line 6
    invoke-direct {v0, v2, v1, v1}, Lbo0/i;-><init>(Ljava/util/List;ZZ)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lbo0/k;->h:Ltr0/b;

    .line 13
    .line 14
    iput-object p2, p0, Lbo0/k;->i:Lyn0/r;

    .line 15
    .line 16
    iput-object p3, p0, Lbo0/k;->j:Lyn0/d;

    .line 17
    .line 18
    iput-object p4, p0, Lbo0/k;->k:Lyn0/n;

    .line 19
    .line 20
    iput-object p5, p0, Lbo0/k;->l:Lij0/a;

    .line 21
    .line 22
    iput-object p6, p0, Lbo0/k;->m:Lqf0/g;

    .line 23
    .line 24
    iput-object v2, p0, Lbo0/k;->o:Ljava/util/List;

    .line 25
    .line 26
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    new-instance p2, Lbo0/g;

    .line 31
    .line 32
    const/4 p3, 0x0

    .line 33
    const/4 p4, 0x0

    .line 34
    invoke-direct {p2, p0, p4, p3}, Lbo0/g;-><init>(Lbo0/k;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    const/4 p0, 0x3

    .line 38
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    return-void
.end method
