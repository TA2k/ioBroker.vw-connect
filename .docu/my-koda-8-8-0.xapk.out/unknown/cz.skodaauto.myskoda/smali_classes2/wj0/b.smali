.class public final Lwj0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lwj0/c;

.field public final b:Lwj0/d;

.field public final c:Lwj0/e;


# direct methods
.method public constructor <init>(Lwj0/c;Lwj0/d;Lwj0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwj0/b;->a:Lwj0/c;

    .line 5
    .line 6
    iput-object p2, p0, Lwj0/b;->b:Lwj0/d;

    .line 7
    .line 8
    iput-object p3, p0, Lwj0/b;->c:Lwj0/e;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lwj0/b;->a:Lwj0/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lwj0/c;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lwj0/b;->b:Lwj0/d;

    .line 7
    .line 8
    invoke-virtual {v0}, Lwj0/d;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lwj0/b;->c:Lwj0/e;

    .line 12
    .line 13
    invoke-virtual {p0}, Lwj0/e;->invoke()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    return-object p0
.end method
