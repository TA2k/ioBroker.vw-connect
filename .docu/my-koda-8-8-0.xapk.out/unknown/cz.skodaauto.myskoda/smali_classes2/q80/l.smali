.class public final Lq80/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lq80/p;

.field public final b:Lq80/c;


# direct methods
.method public constructor <init>(Lq80/p;Lq80/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq80/l;->a:Lq80/p;

    .line 5
    .line 6
    iput-object p2, p0, Lq80/l;->b:Lq80/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Ljava/util/List;

    .line 5
    .line 6
    iget-object v2, p0, Lq80/l;->b:Lq80/c;

    .line 7
    .line 8
    check-cast v2, Lo80/a;

    .line 9
    .line 10
    iput-object v1, v2, Lo80/a;->a:Ljava/util/List;

    .line 11
    .line 12
    iget-object p0, p0, Lq80/l;->a:Lq80/p;

    .line 13
    .line 14
    check-cast p0, Liy/b;

    .line 15
    .line 16
    sget-object v1, Lly/b;->s3:Lly/b;

    .line 17
    .line 18
    invoke-interface {p0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 19
    .line 20
    .line 21
    return-object v0
.end method
