.class public final Li20/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Li20/c;


# direct methods
.method public constructor <init>(Li20/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li20/k;->a:Li20/c;

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
    check-cast v1, Lvg0/c;

    .line 5
    .line 6
    iget-object p0, p0, Li20/k;->a:Li20/c;

    .line 7
    .line 8
    check-cast p0, Liy/b;

    .line 9
    .line 10
    sget-object v1, Lvg0/d;->a:Lvg0/d;

    .line 11
    .line 12
    invoke-virtual {p0, v1}, Liy/b;->d(Lvg0/d;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method
