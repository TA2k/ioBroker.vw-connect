.class public final synthetic Ll61/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:F

.field public final synthetic f:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

.field public final synthetic g:Z


# direct methods
.method public synthetic constructor <init>(Lx2/s;FLtechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll61/a;->d:Lx2/s;

    .line 5
    .line 6
    iput p2, p0, Ll61/a;->e:F

    .line 7
    .line 8
    iput-object p3, p0, Ll61/a;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 9
    .line 10
    iput-boolean p4, p0, Ll61/a;->g:Z

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    move-object v4, p1

    .line 2
    check-cast v4, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const/4 p1, 0x7

    .line 10
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 11
    .line 12
    .line 13
    move-result v5

    .line 14
    iget-object v0, p0, Ll61/a;->d:Lx2/s;

    .line 15
    .line 16
    iget v1, p0, Ll61/a;->e:F

    .line 17
    .line 18
    iget-object v2, p0, Ll61/a;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 19
    .line 20
    iget-boolean v3, p0, Ll61/a;->g:Z

    .line 21
    .line 22
    invoke-static/range {v0 .. v5}, Ll61/c;->b(Lx2/s;FLtechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZLl2/o;I)V

    .line 23
    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0
.end method
