.class public final Luk0/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/b0;

.field public final b:Lnp0/c;


# direct methods
.method public constructor <init>(Lkf0/b0;Lnp0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luk0/t0;->a:Lkf0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Luk0/t0;->b:Lnp0/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lqp0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Luk0/t0;->b(Lqp0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lqp0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance p2, Ltr0/e;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const/16 v1, 0x10

    .line 5
    .line 6
    invoke-direct {p2, v1, p0, p1, v0}, Ltr0/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    new-instance p0, Lyy0/m1;

    .line 10
    .line 11
    invoke-direct {p0, p2}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method
