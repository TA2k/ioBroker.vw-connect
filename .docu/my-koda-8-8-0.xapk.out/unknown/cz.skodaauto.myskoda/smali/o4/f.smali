.class public final Lo4/f;
.super Ls6/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:Ll2/j1;

.field public final synthetic e:Lhu/q;


# direct methods
.method public constructor <init>(Ll2/j1;Lhu/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo4/f;->d:Ll2/j1;

    .line 5
    .line 6
    iput-object p2, p0, Lo4/f;->e:Lhu/q;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 1

    .line 1
    iget-object p0, p0, Lo4/f;->e:Lhu/q;

    .line 2
    .line 3
    sget-object v0, Lo4/i;->a:Lo4/j;

    .line 4
    .line 5
    iput-object v0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 6
    .line 7
    return-void
.end method

.method public final b()V
    .locals 2

    .line 1
    iget-object v0, p0, Lo4/f;->d:Ll2/j1;

    .line 2
    .line 3
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lo4/j;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, v1}, Lo4/j;-><init>(Z)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lo4/f;->e:Lhu/q;

    .line 15
    .line 16
    iput-object v0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 17
    .line 18
    return-void
.end method
