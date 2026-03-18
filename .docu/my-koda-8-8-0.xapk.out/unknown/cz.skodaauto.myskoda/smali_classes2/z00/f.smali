.class public final Lz00/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lz00/a;

.field public final b:Lz00/d;


# direct methods
.method public constructor <init>(Lz00/a;Lz00/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz00/f;->a:Lz00/a;

    .line 5
    .line 6
    iput-object p2, p0, Lz00/f;->b:Lz00/d;

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
    check-cast v1, Ljava/lang/Boolean;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    iget-object v2, p0, Lz00/f;->b:Lz00/d;

    .line 11
    .line 12
    check-cast v2, Lx00/a;

    .line 13
    .line 14
    iput-boolean v1, v2, Lx00/a;->b:Z

    .line 15
    .line 16
    iget-object p0, p0, Lz00/f;->a:Lz00/a;

    .line 17
    .line 18
    check-cast p0, Liy/b;

    .line 19
    .line 20
    sget-object v1, Lly/b;->L:Lly/b;

    .line 21
    .line 22
    invoke-interface {p0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method
