.class public final Ljt0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llt0/d;
.implements Lme0/b;


# instance fields
.field public final a:Lwe0/a;

.field public final b:Lyy0/c2;


# direct methods
.method public constructor <init>(Lwe0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljt0/a;->a:Lwe0/a;

    .line 5
    .line 6
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 7
    .line 8
    .line 9
    sget-object p1, Lne0/d;->a:Lne0/d;

    .line 10
    .line 11
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iput-object p1, p0, Ljt0/a;->b:Lyy0/c2;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p1, p0, Ljt0/a;->b:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    sget-object v1, Lne0/d;->a:Lne0/d;

    .line 8
    .line 9
    invoke-virtual {p1, v0, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Ljt0/a;->a:Lwe0/a;

    .line 13
    .line 14
    check-cast p0, Lwe0/c;

    .line 15
    .line 16
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 17
    .line 18
    .line 19
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0
.end method
