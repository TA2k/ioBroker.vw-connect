.class public final La90/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:La90/q;


# direct methods
.method public constructor <init>(La90/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La90/v;->a:La90/q;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, La90/v;->a:La90/q;

    .line 2
    .line 3
    check-cast p0, Ly80/a;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iput-object v0, p0, Ly80/a;->e:Ljava/time/LocalDate;

    .line 7
    .line 8
    iput-object v0, p0, Ly80/a;->f:Ljava/time/LocalTime;

    .line 9
    .line 10
    iput-object v0, p0, Ly80/a;->g:Lb90/s;

    .line 11
    .line 12
    iput-object v0, p0, Ly80/a;->h:Lb90/m;

    .line 13
    .line 14
    iput-object v0, p0, Ly80/a;->i:Lb90/a;

    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    return-object p0
.end method
