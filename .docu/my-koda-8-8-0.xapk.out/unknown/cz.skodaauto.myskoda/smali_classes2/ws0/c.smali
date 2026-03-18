.class public final Lws0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lus0/b;


# direct methods
.method public constructor <init>(Lus0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lws0/c;->a:Lus0/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lws0/b;

    .line 4
    .line 5
    iget-object v2, p0, Lws0/c;->a:Lus0/b;

    .line 6
    .line 7
    const-string p0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string p0, "name"

    .line 14
    .line 15
    const/4 v4, 0x0

    .line 16
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object p0, v2, Lus0/b;->a:Lxl0/f;

    .line 20
    .line 21
    new-instance v1, Lo10/l;

    .line 22
    .line 23
    const/4 v5, 0x0

    .line 24
    const/16 v6, 0xe

    .line 25
    .line 26
    invoke-direct/range {v1 .. v6}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0, v1}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method
