.class public final Lbh0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lbh0/a;


# direct methods
.method public constructor <init>(Lbh0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbh0/b;->a:Lbh0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ldh0/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lbh0/b;->b(Ldh0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ldh0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p1, p1, Ldh0/a;->d:Ljava/lang/String;

    .line 2
    .line 3
    iget-object p0, p0, Lbh0/b;->a:Lbh0/a;

    .line 4
    .line 5
    check-cast p0, Lzg0/a;

    .line 6
    .line 7
    iget-object v0, p0, Lzg0/a;->h:Lyy0/q1;

    .line 8
    .line 9
    invoke-virtual {v0}, Lyy0/q1;->q()V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lzg0/a;->f:Lyy0/q1;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    invoke-static {v0, p2}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
