.class public final Ljn/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public synthetic d:F

.field public final synthetic e:Lvy0/b0;

.field public final synthetic f:Lc1/c;

.field public final synthetic g:Ljava/util/List;

.field public final synthetic h:Ljava/lang/Integer;

.field public final synthetic i:F

.field public final synthetic j:Lay0/k;


# direct methods
.method public constructor <init>(Lvy0/b0;Lc1/c;Ljava/util/List;Ljava/lang/Integer;FLay0/k;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ljn/j;->e:Lvy0/b0;

    .line 2
    .line 3
    iput-object p2, p0, Ljn/j;->f:Lc1/c;

    .line 4
    .line 5
    iput-object p3, p0, Ljn/j;->g:Ljava/util/List;

    .line 6
    .line 7
    iput-object p4, p0, Ljn/j;->h:Ljava/lang/Integer;

    .line 8
    .line 9
    iput p5, p0, Ljn/j;->i:F

    .line 10
    .line 11
    iput-object p6, p0, Ljn/j;->j:Lay0/k;

    .line 12
    .line 13
    const/4 p1, 0x3

    .line 14
    invoke-direct {p0, p1, p7}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    move-object v7, p3

    .line 10
    check-cast v7, Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    new-instance v0, Ljn/j;

    .line 13
    .line 14
    iget v5, p0, Ljn/j;->i:F

    .line 15
    .line 16
    iget-object v6, p0, Ljn/j;->j:Lay0/k;

    .line 17
    .line 18
    iget-object v1, p0, Ljn/j;->e:Lvy0/b0;

    .line 19
    .line 20
    iget-object v2, p0, Ljn/j;->f:Lc1/c;

    .line 21
    .line 22
    iget-object v3, p0, Ljn/j;->g:Ljava/util/List;

    .line 23
    .line 24
    iget-object v4, p0, Ljn/j;->h:Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-direct/range {v0 .. v7}, Ljn/j;-><init>(Lvy0/b0;Lc1/c;Ljava/util/List;Ljava/lang/Integer;FLay0/k;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    iput p1, v0, Ljn/j;->d:F

    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    invoke-virtual {v0, p0}, Ljn/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget v3, p0, Ljn/j;->d:F

    .line 7
    .line 8
    new-instance v1, Ljn/i;

    .line 9
    .line 10
    iget-object v7, p0, Ljn/j;->j:Lay0/k;

    .line 11
    .line 12
    const/4 v8, 0x0

    .line 13
    iget-object v2, p0, Ljn/j;->f:Lc1/c;

    .line 14
    .line 15
    iget-object v4, p0, Ljn/j;->g:Ljava/util/List;

    .line 16
    .line 17
    iget-object v5, p0, Ljn/j;->h:Ljava/lang/Integer;

    .line 18
    .line 19
    iget v6, p0, Ljn/j;->i:F

    .line 20
    .line 21
    invoke-direct/range {v1 .. v8}, Ljn/i;-><init>(Lc1/c;FLjava/util/List;Ljava/lang/Integer;FLay0/k;Lkotlin/coroutines/Continuation;)V

    .line 22
    .line 23
    .line 24
    const/4 p1, 0x3

    .line 25
    iget-object p0, p0, Ljn/j;->e:Lvy0/b0;

    .line 26
    .line 27
    const/4 v0, 0x0

    .line 28
    invoke-static {p0, v0, v0, v1, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0
.end method
