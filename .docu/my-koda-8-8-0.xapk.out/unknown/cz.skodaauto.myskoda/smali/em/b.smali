.class public final Lem/b;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Ldm/i;

.field public e:Lyl/d;

.field public f:Lmm/g;

.field public g:Ljava/lang/Object;

.field public h:Lmm/n;

.field public i:Lyl/f;

.field public j:I

.field public synthetic k:Ljava/lang/Object;

.field public final synthetic l:Lem/f;

.field public m:I


# direct methods
.method public constructor <init>(Lem/f;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lem/b;->l:Lem/f;

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
    iput-object p1, p0, Lem/b;->k:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lem/b;->m:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lem/b;->m:I

    .line 9
    .line 10
    const/4 v5, 0x0

    .line 11
    const/4 v6, 0x0

    .line 12
    iget-object v0, p0, Lem/b;->l:Lem/f;

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
    invoke-static/range {v0 .. v7}, Lem/f;->a(Lem/f;Ldm/i;Lyl/d;Lmm/g;Ljava/lang/Object;Lmm/n;Lyl/f;Lrx0/c;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
