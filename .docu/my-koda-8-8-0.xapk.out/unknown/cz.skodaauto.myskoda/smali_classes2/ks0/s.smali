.class public final Lks0/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lks0/b;

.field public final b:Lsg0/a;


# direct methods
.method public constructor <init>(Lks0/b;Lsg0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lks0/s;->a:Lks0/b;

    .line 5
    .line 6
    iput-object p2, p0, Lks0/s;->b:Lsg0/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lvg0/b;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Lks0/s;->b:Lsg0/a;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    iput-object v2, v1, Lsg0/a;->b:Lss0/n;

    .line 13
    .line 14
    iput-object v2, v1, Lsg0/a;->a:Ljava/lang/String;

    .line 15
    .line 16
    iget-object p0, p0, Lks0/s;->a:Lks0/b;

    .line 17
    .line 18
    check-cast p0, Liy/b;

    .line 19
    .line 20
    new-instance v1, Lul0/c;

    .line 21
    .line 22
    sget-object v2, Lly/b;->Z:Lly/b;

    .line 23
    .line 24
    const/4 v5, 0x0

    .line 25
    const/16 v6, 0x38

    .line 26
    .line 27
    const/4 v3, 0x1

    .line 28
    const/4 v4, 0x0

    .line 29
    invoke-direct/range {v1 .. v6}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, v1}, Liy/b;->b(Lul0/e;)V

    .line 33
    .line 34
    .line 35
    return-object v0
.end method
