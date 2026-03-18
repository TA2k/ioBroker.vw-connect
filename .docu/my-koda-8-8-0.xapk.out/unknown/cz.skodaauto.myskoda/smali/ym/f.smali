.class public final Lym/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lym/g;

.field public final synthetic e:Lum/a;

.field public final synthetic f:F

.field public final synthetic g:Z


# direct methods
.method public constructor <init>(Lym/g;Lum/a;FZLkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lym/f;->d:Lym/g;

    .line 2
    .line 3
    iput-object p2, p0, Lym/f;->e:Lum/a;

    .line 4
    .line 5
    iput p3, p0, Lym/f;->f:F

    .line 6
    .line 7
    iput-boolean p4, p0, Lym/f;->g:Z

    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6

    .line 1
    new-instance v0, Lym/f;

    .line 2
    .line 3
    iget v3, p0, Lym/f;->f:F

    .line 4
    .line 5
    iget-boolean v4, p0, Lym/f;->g:Z

    .line 6
    .line 7
    iget-object v1, p0, Lym/f;->d:Lym/g;

    .line 8
    .line 9
    iget-object v2, p0, Lym/f;->e:Lum/a;

    .line 10
    .line 11
    move-object v5, p1

    .line 12
    invoke-direct/range {v0 .. v5}, Lym/f;-><init>(Lym/g;Lum/a;FZLkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lym/f;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lym/f;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lym/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lym/f;->e:Lum/a;

    .line 7
    .line 8
    iget-object v0, p0, Lym/f;->d:Lym/g;

    .line 9
    .line 10
    iget-object v1, v0, Lym/g;->l:Ll2/j1;

    .line 11
    .line 12
    invoke-virtual {v1, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iget p1, p0, Lym/f;->f:F

    .line 16
    .line 17
    invoke-virtual {v0, p1}, Lym/g;->f(F)V

    .line 18
    .line 19
    .line 20
    const/4 p1, 0x1

    .line 21
    invoke-virtual {v0, p1}, Lym/g;->e(I)V

    .line 22
    .line 23
    .line 24
    iget-object p1, v0, Lym/g;->d:Ll2/j1;

    .line 25
    .line 26
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 27
    .line 28
    invoke-virtual {p1, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    iget-boolean p0, p0, Lym/f;->g:Z

    .line 32
    .line 33
    if-eqz p0, :cond_0

    .line 34
    .line 35
    iget-object p0, v0, Lym/g;->o:Ll2/j1;

    .line 36
    .line 37
    const-wide/high16 v0, -0x8000000000000000L

    .line 38
    .line 39
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    return-object p0
.end method
