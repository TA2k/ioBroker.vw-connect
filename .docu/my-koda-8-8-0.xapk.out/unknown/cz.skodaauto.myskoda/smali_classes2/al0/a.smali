.class public final Lal0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lal0/b0;

.field public final b:Lck0/a;


# direct methods
.method public constructor <init>(Lal0/b0;Lck0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lal0/a;->a:Lal0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lal0/a;->b:Lck0/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lal0/a;->a:Lal0/b0;

    .line 2
    .line 3
    check-cast v0, Lyk0/e;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    iput-object v1, v0, Lyk0/e;->e:Ljava/util/UUID;

    .line 7
    .line 8
    iget-object p0, p0, Lal0/a;->b:Lck0/a;

    .line 9
    .line 10
    invoke-virtual {p0}, Lck0/a;->invoke()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method
