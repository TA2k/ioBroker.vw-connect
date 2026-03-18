.class public final Lyn0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lyn0/a;

.field public final b:Lyn0/j;


# direct methods
.method public constructor <init>(Lyn0/a;Lyn0/j;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyn0/h;->a:Lyn0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lyn0/h;->b:Lyn0/j;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Ljava/util/List;

    .line 2
    .line 3
    iget-object v0, p0, Lyn0/h;->a:Lyn0/a;

    .line 4
    .line 5
    check-cast v0, Lwn0/a;

    .line 6
    .line 7
    const-string v1, "climateTimers"

    .line 8
    .line 9
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, v0, Lwn0/a;->m:Lyy0/c2;

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-virtual {v1, v2, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lyn0/h;->b:Lyn0/j;

    .line 22
    .line 23
    check-cast p0, Liy/b;

    .line 24
    .line 25
    sget-object p1, Lly/b;->J:Lly/b;

    .line 26
    .line 27
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 28
    .line 29
    .line 30
    iget-object p0, v0, Lwn0/a;->p:Lyy0/k1;

    .line 31
    .line 32
    invoke-static {p0, p2}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method
