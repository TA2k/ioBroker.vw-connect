.class public final Lcn/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcn/b;


# instance fields
.field public final a:Lbn/f;

.field public final b:Lbn/a;

.field public final c:Z

.field public final d:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Lbn/f;Lbn/a;ZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lcn/a;->a:Lbn/f;

    .line 5
    .line 6
    iput-object p3, p0, Lcn/a;->b:Lbn/a;

    .line 7
    .line 8
    iput-boolean p4, p0, Lcn/a;->c:Z

    .line 9
    .line 10
    iput-boolean p5, p0, Lcn/a;->d:Z

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Lum/j;Lum/a;Ldn/b;)Lwm/c;
    .locals 0

    .line 1
    new-instance p2, Lwm/f;

    .line 2
    .line 3
    invoke-direct {p2, p1, p3, p0}, Lwm/f;-><init>(Lum/j;Ldn/b;Lcn/a;)V

    .line 4
    .line 5
    .line 6
    return-object p2
.end method
