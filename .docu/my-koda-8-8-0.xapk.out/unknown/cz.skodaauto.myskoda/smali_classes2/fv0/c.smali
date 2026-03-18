.class public final Lfv0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhv0/z;
.implements Lme0/a;


# instance fields
.field public final a:Lyy0/c2;

.field public final b:Lyy0/l1;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Liv0/g;->a:Liv0/g;

    .line 5
    .line 6
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Lfv0/c;->a:Lyy0/c2;

    .line 11
    .line 12
    new-instance v1, Lyy0/l1;

    .line 13
    .line 14
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 15
    .line 16
    .line 17
    iput-object v1, p0, Lfv0/c;->b:Lyy0/l1;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Lfv0/c;->a:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    sget-object v0, Liv0/g;->a:Liv0/g;

    .line 8
    .line 9
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method
