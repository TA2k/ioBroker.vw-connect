.class public final Le60/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbn0/g;


# direct methods
.method public constructor <init>(Lbn0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le60/f;->a:Lbn0/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Lbn0/c;

    .line 2
    .line 3
    const-string v1, "vehicle-access"

    .line 4
    .line 5
    const-string v2, "honk-and-flash"

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Lbn0/c;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Le60/f;->a:Lbn0/g;

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lbn0/g;->a(Lbn0/c;)Lzy0/j;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    new-instance v0, Lal0/j0;

    .line 17
    .line 18
    const/4 v1, 0x3

    .line 19
    invoke-direct {v0, p0, v1}, Lal0/j0;-><init>(Lzy0/j;I)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method
