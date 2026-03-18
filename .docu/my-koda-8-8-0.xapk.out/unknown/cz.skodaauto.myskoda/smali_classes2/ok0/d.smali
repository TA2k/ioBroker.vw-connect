.class public final Lok0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lfg0/d;

.field public final b:Lfg0/c;

.field public final c:Ltn0/d;


# direct methods
.method public constructor <init>(Lfg0/d;Lfg0/c;Ltn0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lok0/d;->a:Lfg0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lok0/d;->b:Lfg0/c;

    .line 7
    .line 8
    iput-object p3, p0, Lok0/d;->c:Ltn0/d;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lok0/d;->c:Ltn0/d;

    .line 2
    .line 3
    sget-object v1, Lun0/a;->e:Lun0/a;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ltn0/d;->a(Lun0/a;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    new-instance v1, Lok0/b;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-direct {v1, v2, p0, v3}, Lok0/b;-><init>(Lkotlin/coroutines/Continuation;Lok0/d;I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
