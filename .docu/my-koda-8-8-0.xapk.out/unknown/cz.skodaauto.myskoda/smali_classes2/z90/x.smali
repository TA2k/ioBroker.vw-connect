.class public final Lz90/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lz90/p;


# direct methods
.method public constructor <init>(Lz90/p;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz90/x;->a:Lz90/p;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Laa0/c;

    .line 5
    .line 6
    iget-object p0, p0, Lz90/x;->a:Lz90/p;

    .line 7
    .line 8
    check-cast p0, Lx90/a;

    .line 9
    .line 10
    iget-object p0, p0, Lx90/a;->d:Lyy0/c2;

    .line 11
    .line 12
    invoke-virtual {p0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method
