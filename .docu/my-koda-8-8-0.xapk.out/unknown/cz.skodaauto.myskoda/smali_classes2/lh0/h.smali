.class public final Llh0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Llh0/j;


# direct methods
.method public constructor <init>(Llh0/j;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llh0/h;->a:Llh0/j;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    sget-object v0, Lmh0/b;->f:Lmh0/b;

    .line 4
    .line 5
    new-instance v1, Lmh0/a;

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    invoke-direct {v1, p1, v2, v0, v2}, Lmh0/a;-><init>(Ljava/lang/String;ILmh0/b;Z)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Llh0/h;->a:Llh0/j;

    .line 12
    .line 13
    invoke-virtual {p0, v1, p2}, Llh0/j;->b(Lmh0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
