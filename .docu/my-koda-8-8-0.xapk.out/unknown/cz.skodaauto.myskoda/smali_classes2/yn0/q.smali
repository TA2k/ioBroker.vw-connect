.class public final Lyn0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lyn0/g;

.field public final b:Lyn0/a;


# direct methods
.method public constructor <init>(Lyn0/g;Lyn0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyn0/q;->a:Lyn0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lyn0/q;->b:Lyn0/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lao0/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lyn0/q;->b(Lao0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lao0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lyn0/q;->b:Lyn0/a;

    .line 2
    .line 3
    check-cast v0, Lwn0/a;

    .line 4
    .line 5
    iget-object v1, v0, Lwn0/a;->e:Lyy0/c2;

    .line 6
    .line 7
    invoke-virtual {v1, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lyn0/q;->a:Lyn0/g;

    .line 11
    .line 12
    invoke-virtual {p0}, Lyn0/g;->invoke()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    iget-object p0, v0, Lwn0/a;->h:Lyy0/k1;

    .line 16
    .line 17
    invoke-static {p0, p2}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
