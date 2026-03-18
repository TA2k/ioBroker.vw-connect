.class public final Lug0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lsg0/a;


# direct methods
.method public constructor <init>(Lsg0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lug0/c;->a:Lsg0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lne0/t;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    new-instance v0, Lag/t;

    .line 4
    .line 5
    const/16 v1, 0x10

    .line 6
    .line 7
    invoke-direct {v0, p0, v1}, Lag/t;-><init>(Ljava/lang/Object;I)V

    .line 8
    .line 9
    .line 10
    invoke-static {p1, v0}, Lbb/j0;->c(Lne0/t;Lay0/k;)Lne0/t;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 p1, 0x0

    .line 16
    :goto_0
    iget-object p0, p0, Lug0/c;->a:Lsg0/a;

    .line 17
    .line 18
    iput-object p1, p0, Lsg0/a;->c:Lne0/t;

    .line 19
    .line 20
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lne0/t;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lug0/c;->a(Lne0/t;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
