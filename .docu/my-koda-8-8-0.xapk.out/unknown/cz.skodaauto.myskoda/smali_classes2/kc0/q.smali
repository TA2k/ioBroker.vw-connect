.class public final Lkc0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkc0/g;


# direct methods
.method public constructor <init>(Lkc0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkc0/q;->a:Lkc0/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p0, p0, Lkc0/q;->a:Lkc0/g;

    .line 4
    .line 5
    check-cast p0, Lic0/p;

    .line 6
    .line 7
    sget-object p1, Lge0/b;->a:Lcz0/e;

    .line 8
    .line 9
    new-instance v0, Lic0/g;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, p0, v1, v2}, Lic0/g;-><init>(Lic0/p;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    invoke-static {p1, v0, p2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
