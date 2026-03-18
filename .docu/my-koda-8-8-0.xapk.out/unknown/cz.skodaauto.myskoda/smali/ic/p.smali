.class public final Lic/p;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# instance fields
.field public synthetic d:Llc/q;

.field public synthetic e:Ldc/t;

.field public synthetic f:Lac/a0;

.field public synthetic g:Z

.field public final synthetic h:Lic/q;


# direct methods
.method public constructor <init>(Lic/q;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lic/p;->h:Lic/q;

    .line 2
    .line 3
    const/4 p1, 0x5

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Llc/q;

    .line 2
    .line 3
    check-cast p2, Ldc/t;

    .line 4
    .line 5
    check-cast p3, Lac/a0;

    .line 6
    .line 7
    check-cast p4, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p4

    .line 13
    check-cast p5, Lkotlin/coroutines/Continuation;

    .line 14
    .line 15
    new-instance v0, Lic/p;

    .line 16
    .line 17
    iget-object p0, p0, Lic/p;->h:Lic/q;

    .line 18
    .line 19
    invoke-direct {v0, p0, p5}, Lic/p;-><init>(Lic/q;Lkotlin/coroutines/Continuation;)V

    .line 20
    .line 21
    .line 22
    iput-object p1, v0, Lic/p;->d:Llc/q;

    .line 23
    .line 24
    iput-object p2, v0, Lic/p;->e:Ldc/t;

    .line 25
    .line 26
    iput-object p3, v0, Lic/p;->f:Lac/a0;

    .line 27
    .line 28
    iput-boolean p4, v0, Lic/p;->g:Z

    .line 29
    .line 30
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Lic/p;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lic/p;->d:Llc/q;

    .line 2
    .line 3
    iget-object v1, p0, Lic/p;->e:Ldc/t;

    .line 4
    .line 5
    iget-object v2, p0, Lic/p;->f:Lac/a0;

    .line 6
    .line 7
    iget-boolean v3, p0, Lic/p;->g:Z

    .line 8
    .line 9
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 10
    .line 11
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    new-instance p1, Le2/g;

    .line 15
    .line 16
    iget-object p0, p0, Lic/p;->h:Lic/q;

    .line 17
    .line 18
    invoke-direct {p1, p0, v1, v2, v3}, Le2/g;-><init>(Lic/q;Ldc/t;Lac/a0;Z)V

    .line 19
    .line 20
    .line 21
    invoke-static {v0, p1}, Llc/a;->b(Llc/q;Lay0/k;)Llc/q;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method
