.class public final synthetic Ll30/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Li91/c2;

.field public final synthetic e:F

.field public final synthetic f:Z

.field public final synthetic g:Z


# direct methods
.method public synthetic constructor <init>(Li91/c2;FZZI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll30/c;->d:Li91/c2;

    .line 5
    .line 6
    iput p2, p0, Ll30/c;->e:F

    .line 7
    .line 8
    iput-boolean p3, p0, Ll30/c;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Ll30/c;->g:Z

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
    const/4 p1, 0x1

    .line 10
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 11
    .line 12
    .line 13
    move-result v5

    .line 14
    iget-object v0, p0, Ll30/c;->d:Li91/c2;

    .line 15
    .line 16
    iget v1, p0, Ll30/c;->e:F

    .line 17
    .line 18
    iget-boolean v2, p0, Ll30/c;->f:Z

    .line 19
    .line 20
    iget-boolean v3, p0, Ll30/c;->g:Z

    .line 21
    .line 22
    invoke-static/range {v0 .. v5}, Llp/ne;->d(Li91/c2;FZZLl2/o;I)V

    .line 23
    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0
.end method
