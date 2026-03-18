.class public final Lep0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Lcp0/e;

.field public final c:Lcp0/l;

.field public final d:Lhu0/b;


# direct methods
.method public constructor <init>(Lkf0/o;Lcp0/e;Lcp0/l;Lhu0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lep0/a;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lep0/a;->b:Lcp0/e;

    .line 7
    .line 8
    iput-object p3, p0, Lep0/a;->c:Lcp0/l;

    .line 9
    .line 10
    iput-object p4, p0, Lep0/a;->d:Lhu0/b;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lep0/a;->a:Lkf0/o;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lal0/f;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x3

    .line 11
    invoke-direct {v1, v2, p0, v3}, Lal0/f;-><init>(Lkotlin/coroutines/Continuation;Ltr0/d;I)V

    .line 12
    .line 13
    .line 14
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method
