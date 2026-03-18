.class public final Lol/b;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lol/f;

.field public e:Lnl/m;

.field public f:Lil/c;

.field public g:Ltl/h;

.field public h:Ljava/lang/Object;

.field public i:Ltl/l;

.field public j:Lil/d;

.field public k:I

.field public synthetic l:Ljava/lang/Object;

.field public final synthetic m:Lol/f;

.field public n:I


# direct methods
.method public constructor <init>(Lol/f;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lol/b;->m:Lol/f;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iput-object p1, p0, Lol/b;->l:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lol/b;->n:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lol/b;->n:I

    .line 9
    .line 10
    const/4 v5, 0x0

    .line 11
    const/4 v6, 0x0

    .line 12
    iget-object v0, p0, Lol/b;->m:Lol/f;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    const/4 v2, 0x0

    .line 16
    const/4 v3, 0x0

    .line 17
    const/4 v4, 0x0

    .line 18
    move-object v7, p0

    .line 19
    invoke-static/range {v0 .. v7}, Lol/f;->a(Lol/f;Lnl/m;Lil/c;Ltl/h;Ljava/lang/Object;Ltl/l;Lil/d;Lrx0/c;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
