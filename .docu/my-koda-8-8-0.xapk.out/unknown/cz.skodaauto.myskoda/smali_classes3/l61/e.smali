.class public final synthetic Ll61/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(FZZI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Ll61/e;->d:F

    .line 5
    .line 6
    iput-boolean p2, p0, Ll61/e;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Ll61/e;->f:Z

    .line 9
    .line 10
    iput p4, p0, Ll61/e;->g:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Ll2/o;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Integer;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    iget p2, p0, Ll61/e;->g:I

    .line 9
    .line 10
    or-int/lit8 p2, p2, 0x1

    .line 11
    .line 12
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 13
    .line 14
    .line 15
    move-result p2

    .line 16
    iget v0, p0, Ll61/e;->d:F

    .line 17
    .line 18
    iget-boolean v1, p0, Ll61/e;->e:Z

    .line 19
    .line 20
    iget-boolean p0, p0, Ll61/e;->f:Z

    .line 21
    .line 22
    invoke-static {v0, v1, p0, p1, p2}, Llp/bf;->e(FZZLl2/o;I)V

    .line 23
    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0
.end method
