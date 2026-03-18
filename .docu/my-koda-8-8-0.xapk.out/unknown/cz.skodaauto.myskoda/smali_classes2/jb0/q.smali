.class public final Ljb0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llb0/e;
.implements Lme0/a;
.implements Lme0/b;


# instance fields
.field public final synthetic a:Lcom/google/firebase/messaging/w;


# direct methods
.method public constructor <init>(Lwe0/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lcom/google/firebase/messaging/w;

    .line 5
    .line 6
    invoke-direct {v0, p1}, Lcom/google/firebase/messaging/w;-><init>(Lwe0/a;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Ljb0/q;->a:Lcom/google/firebase/messaging/w;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Ljb0/q;->a:Lcom/google/firebase/messaging/w;

    .line 2
    .line 3
    iget-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p1, Lyy0/c2;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    move-object v1, v0

    .line 12
    check-cast v1, Lne0/s;

    .line 13
    .line 14
    sget-object v1, Lne0/d;->a:Lne0/d;

    .line 15
    .line 16
    invoke-virtual {p1, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Lwe0/a;

    .line 25
    .line 26
    check-cast p0, Lwe0/c;

    .line 27
    .line 28
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0
.end method
