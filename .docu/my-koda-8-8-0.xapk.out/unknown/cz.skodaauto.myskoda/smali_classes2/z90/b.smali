.class public final Lz90/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lx90/b;


# direct methods
.method public constructor <init>(Lx90/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz90/b;->a:Lx90/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lz90/b;->a:Lx90/b;

    .line 6
    .line 7
    iget-object v1, p0, Lx90/b;->a:Lxl0/f;

    .line 8
    .line 9
    new-instance v2, Llo0/b;

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    const/16 v4, 0x1d

    .line 13
    .line 14
    invoke-direct {v2, v4, p0, v0, v3}, Llo0/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1, v2}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
