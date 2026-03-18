.class public final Lat0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lat0/c;


# direct methods
.method public constructor <init>(Lat0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lat0/o;->a:Lat0/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lbt0/b;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lat0/o;->a:Lat0/c;

    .line 2
    .line 3
    check-cast p0, Lys0/a;

    .line 4
    .line 5
    iget-object p0, p0, Lys0/a;->a:Lyy0/c2;

    .line 6
    .line 7
    new-instance v0, Lbt0/a;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-direct {v0, p1, v1}, Lbt0/a;-><init>(Lbt0/b;Ljava/lang/Long;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, v1, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
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
    check-cast v1, Lbt0/b;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lat0/o;->a(Lbt0/b;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
