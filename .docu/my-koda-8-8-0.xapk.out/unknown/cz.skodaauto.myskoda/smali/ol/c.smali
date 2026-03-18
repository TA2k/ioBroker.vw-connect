.class public final Lol/c;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lol/f;

.field public e:Ltl/h;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public h:Lkotlin/jvm/internal/f0;

.field public i:Lkotlin/jvm/internal/f0;

.field public j:Lkotlin/jvm/internal/f0;

.field public k:Lkotlin/jvm/internal/f0;

.field public synthetic l:Ljava/lang/Object;

.field public final synthetic m:Lol/f;

.field public n:I


# direct methods
.method public constructor <init>(Lol/f;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lol/c;->m:Lol/f;

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
    .locals 6

    .line 1
    iput-object p1, p0, Lol/c;->l:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lol/c;->n:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lol/c;->n:I

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    const/4 v4, 0x0

    .line 12
    iget-object v0, p0, Lol/c;->m:Lol/f;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    const/4 v2, 0x0

    .line 16
    move-object v5, p0

    .line 17
    invoke-static/range {v0 .. v5}, Lol/f;->b(Lol/f;Ltl/h;Ljava/lang/Object;Ltl/l;Lil/d;Lrx0/c;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
